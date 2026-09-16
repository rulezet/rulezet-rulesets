rule Virus_Hijack_Trojan_GenericKDZ_105924_89_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_89_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75fa0703887c5d2621d58987cbab619810f201f5dbe8d68c15fd4f1d3590a903"

  strings:
    $s1 = "Er-[TYEe" fullword ascii
    $s2 = "SegO&-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}