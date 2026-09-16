rule Virus_Hijack_Trojan_GenericKDZ_74550_390 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_390.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a764cf09cca49c00f1b2e64136d16449960013d69a4c296f95fa88436411e22"

  strings:
    $s1 = "BalM!dNF" fullword ascii
    $s2 = ";bUlb)" fullword ascii
    $s3 = "k&HazY" fullword ascii
    $s4 = "AB<wAUP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}