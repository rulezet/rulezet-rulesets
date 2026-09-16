rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34350f98e5d792b9c822833127f6fc464f62225f960b27e9732cc033c0d22592"

  strings:
    $s1 = "***about" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}