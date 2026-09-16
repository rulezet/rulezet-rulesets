rule Virus_Hijack_Trojan_GenericKDZ_98113_366_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_366_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d76d5ccfe1a41f674bc4a96a62494b3875a4626f29a1cce224ed2b3c6e362fd"

  strings:
    $s1 = "k]lALL" fullword ascii
    $s2 = "j&oxyl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}