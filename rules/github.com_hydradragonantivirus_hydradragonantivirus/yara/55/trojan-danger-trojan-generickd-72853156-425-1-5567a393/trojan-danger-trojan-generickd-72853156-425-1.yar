rule Trojan_Danger_Trojan_GenericKD_72853156_425_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_425_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad7e2c18b25148abb0c2f3027aea5c847b07a7416d9d0ca3594615bd6978b859"

  strings:
    $s1 = "TuNd]`" fullword ascii
    $s2 = "Z{HobO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}