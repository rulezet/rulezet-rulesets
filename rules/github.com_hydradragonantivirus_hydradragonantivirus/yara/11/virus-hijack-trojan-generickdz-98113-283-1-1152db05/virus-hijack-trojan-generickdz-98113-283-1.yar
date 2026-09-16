rule Virus_Hijack_Trojan_GenericKDZ_98113_283_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_283_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7de1afaad1a9fcd00005e07bf228d304e4a0aa690852dfc1b0ac637e940b97c"

  strings:
    $s1 = "GrIg`O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}