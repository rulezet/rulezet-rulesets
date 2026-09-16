rule Virus_Hijack_Trojan_GenericKDZ_105924_344_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_344_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e327593a27b0d87cf97ab50bb8db848860325058e9b22f03b0fb4e05d37aec55"

  strings:
    $s1 = "OZ;SCob" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}