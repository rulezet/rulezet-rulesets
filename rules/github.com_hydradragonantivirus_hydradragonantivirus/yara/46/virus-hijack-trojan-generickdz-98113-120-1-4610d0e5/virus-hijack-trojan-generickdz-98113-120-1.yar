rule Virus_Hijack_Trojan_GenericKDZ_98113_120_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_120_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccfb43de7da958d0bdd97c82771853ed7dd88296ee03b350b6c628a3cd6ab1c3"

  strings:
    $s1 = "Q$Pean" fullword ascii
    $s2 = "rOxY$K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}