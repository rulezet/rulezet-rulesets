rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aGIb_Qk_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aGIb!Qk_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f21f5ef86cfe5d2510e9a7a366afb85fe61b96cc2c5db90cbdf5f5c387219b"

  strings:
    $s1 = "hyle}V[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}