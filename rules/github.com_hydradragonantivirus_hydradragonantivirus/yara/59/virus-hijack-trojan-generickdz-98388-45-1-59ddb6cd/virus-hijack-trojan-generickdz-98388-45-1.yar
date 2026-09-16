rule Virus_Hijack_Trojan_GenericKDZ_98388_45_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44855ddf3223f537a22421eced91c9d9d50e5f751c51b35786d3428ce057eae2"

  strings:
    $s1 = "$bier$" fullword ascii
    $s2 = "poNd]K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}