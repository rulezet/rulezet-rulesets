rule Virus_Hijack_Gen_Trojan_ShellObject_lSZ_aaT6Wyj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lSZ@aaT6Wyj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93d31d7dd4ca1cce5b8c4ad55b60a370bba91f251f699c9011a6b4e26939683e"

  strings:
    $s1 = "^whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}