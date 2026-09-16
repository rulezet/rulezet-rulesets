rule Virus_Hijack_Trojan_GenericKDZ_98113_123_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_123_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6c178b9d8a36bbf028d360d5fb42a118d380852cb0fdf9cab7b70d908767919"

  strings:
    $s1 = "hanT#G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}