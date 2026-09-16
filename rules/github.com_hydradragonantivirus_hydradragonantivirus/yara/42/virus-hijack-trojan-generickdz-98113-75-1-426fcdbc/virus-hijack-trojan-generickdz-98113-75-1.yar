rule Virus_Hijack_Trojan_GenericKDZ_98113_75_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9308fbffc12a38bcaed5282e371f7aa9a70773fe81a180c2ca2d7d0b9b637f82"

  strings:
    $s1 = "mARy%Y" fullword ascii
    $s2 = "gErb:n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}