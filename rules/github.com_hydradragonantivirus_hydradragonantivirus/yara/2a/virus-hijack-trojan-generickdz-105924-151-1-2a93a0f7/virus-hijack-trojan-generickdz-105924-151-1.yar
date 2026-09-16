rule Virus_Hijack_Trojan_GenericKDZ_105924_151_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_151_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e5fbd7abd8238d379e46a604b8177b68b6f70ead9a2ed3a66f666f1989b1728"

  strings:
    $s1 = "dynamic method does not support fault clause" fullword wide
    $s2 = "Laragon - fast & powerful local development environment     " fullword wide
    $s3 = "PaneList" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}