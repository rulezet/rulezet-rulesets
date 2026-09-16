rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_aaT6Wyj_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6087a13c2522b2f3ea534c730f37e7cbbbf39707255646961e59bd1defd959b5"

  strings:
    $s1 = "bwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}