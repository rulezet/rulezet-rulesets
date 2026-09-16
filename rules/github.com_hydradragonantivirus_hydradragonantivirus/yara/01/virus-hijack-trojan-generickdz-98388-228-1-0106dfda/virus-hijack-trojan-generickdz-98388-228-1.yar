rule Virus_Hijack_Trojan_GenericKDZ_98388_228_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "188ea9acfb22f090d899a778f5c3835cb4ac9d35fb5dd544ce79f3820424b33a"

  strings:
    $s1 = "X<actU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}