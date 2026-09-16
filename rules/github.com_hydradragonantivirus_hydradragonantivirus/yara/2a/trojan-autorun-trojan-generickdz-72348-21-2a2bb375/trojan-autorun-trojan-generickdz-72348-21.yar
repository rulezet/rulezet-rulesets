rule Trojan_Autorun_Trojan_GenericKDZ_72348_21 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7978f5bd919f0dd224de39c26db5c43cfadbb6269da813afd53828f11bdcb0e6"

  strings:
    $s1 = "q;HIKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}