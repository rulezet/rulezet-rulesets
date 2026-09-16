rule Virus_Hijack_Trojan_GenericKDZ_98388_153_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc1a52207fdf74f29dad29039121b31b90312442c8472c26a8e5b61e322eecd6"

  strings:
    $s1 = "{#YARm" fullword ascii
    $s2 = "1[lEAT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}