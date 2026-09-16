rule Virus_Hijack_Trojan_GenericKDZ_98113_110 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_110.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4350e044ee93c30815927c6ca766129f377e7d5737323438e2542d3926f7d0ae"

  strings:
    $s1 = "heNt$tN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}