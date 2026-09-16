rule Trojan_Autorun_Trojan_GenericKDZ_74320_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.74320_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72ccbf48623fee6aa68f9459ab565cdd3a569b1bd88d57f0e4cd97222ce4b139"

  strings:
    $s1 = "~*miLK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}