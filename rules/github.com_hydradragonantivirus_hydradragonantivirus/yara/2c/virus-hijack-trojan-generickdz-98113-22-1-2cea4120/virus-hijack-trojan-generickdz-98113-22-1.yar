rule Virus_Hijack_Trojan_GenericKDZ_98113_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e4aa83b873cceb49207c81abec762aa0657d8107e93b8599a97fd38e7acf7c6"

  strings:
    $s1 = "rL\"Skoo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}