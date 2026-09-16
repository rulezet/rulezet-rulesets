rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09332933f5fcc2782c6a784049293a0ea36311c0c29f46559ac505d805f19959"

  strings:
    $s1 = "Portions Copyright (c) 1999,2003 Avenger by NhT" fullword ascii
    $s2 = "Common Files\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}