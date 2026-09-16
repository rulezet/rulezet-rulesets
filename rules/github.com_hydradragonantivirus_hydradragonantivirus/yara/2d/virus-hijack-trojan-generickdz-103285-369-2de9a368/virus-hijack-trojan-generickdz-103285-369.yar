rule Virus_Hijack_Trojan_GenericKDZ_103285_369 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_369.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa27c78126a745ad511f9f68f5c29b32afd9efc345b8a4d612998a4e99d67d3c"

  strings:
    $s1 = "Ewpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}