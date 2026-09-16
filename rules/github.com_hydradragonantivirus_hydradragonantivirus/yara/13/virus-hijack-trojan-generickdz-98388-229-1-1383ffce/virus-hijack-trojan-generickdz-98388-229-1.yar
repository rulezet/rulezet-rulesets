rule Virus_Hijack_Trojan_GenericKDZ_98388_229_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93412ad0cfafdc50ec77de5e88ab1634f46e0801eb5ddd1f469d52037aa6ae35"

  strings:
    $s1 = "TASk*e" fullword ascii
    $s2 = "n$FAct" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}