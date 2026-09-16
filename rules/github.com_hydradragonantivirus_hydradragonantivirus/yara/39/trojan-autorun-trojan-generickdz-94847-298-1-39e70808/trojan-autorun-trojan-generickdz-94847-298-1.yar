rule Trojan_Autorun_Trojan_GenericKDZ_94847_298_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_298_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e66c9f40b2bb73ed338c0c4f346ba12da2dbf22ad0ecd83966d395971f17d178"

  strings:
    $s1 = "Jdwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}