rule Virus_Hijack_Gen_Trojan_ShellObject_gyY_aWevApi_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyY@aWevApi_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c02c22706451ecd2347022436ede696f294d1dcf7471b25ace85fac93c542c27"

  strings:
    $s1 = "Jocoseness" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}