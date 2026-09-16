rule Virus_Hijack_Trojan_GenericKDZ_105924_497 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_497.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a38f62db28b09c6ea6fe8eb57f2fad60bede533cd2a9857bbba7021153ec0ef2"

  strings:
    $s1 = "eOPr<gOwl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}