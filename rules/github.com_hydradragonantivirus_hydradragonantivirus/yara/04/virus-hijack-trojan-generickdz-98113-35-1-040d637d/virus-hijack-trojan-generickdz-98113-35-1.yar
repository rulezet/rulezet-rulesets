rule Virus_Hijack_Trojan_GenericKDZ_98113_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b39f616e5d1fc0ded6c03bfac5cfc815ca9190b3f8da208a997893a1aace64d0"

  strings:
    $s1 = "tuSh{J@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}