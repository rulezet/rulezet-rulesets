rule Virus_Hijack_Trojan_GenericKDZ_98388_26_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8622b4c87cb166da61cf9f682cceb7f1b0ca4f628ea827fea1c59aa6d5039883"

  strings:
    $s1 = "Y%rAnn" fullword ascii
    $s2 = "GorA$]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}