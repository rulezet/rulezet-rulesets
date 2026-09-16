rule Virus_Hijack_Trojan_GenericKDZ_98113_349_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_349_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8d716e5cfe55722245c58294cf34c491b70bacf45df0081373b4f19e71a9894"

  strings:
    $s1 = "'\"deUL" fullword ascii
    $s2 = "@sOLD," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}