rule Virus_Hijack_Trojan_GenericKDZ_74550_157_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_157_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aed04ccce3c9ca31580c7928aadc5bb096df5c077d987d1452d47bd0e88514e8"

  strings:
    $s1 = "sure}N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}