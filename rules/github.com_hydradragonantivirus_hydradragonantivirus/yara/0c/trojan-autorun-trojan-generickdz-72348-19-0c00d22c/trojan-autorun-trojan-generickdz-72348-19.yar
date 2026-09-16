rule Trojan_Autorun_Trojan_GenericKDZ_72348_19 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47cd4ae63fc1e5a513729a390c18b70d66f46437ebae7bb3e80ee4908e5f90fe"

  strings:
    $s1 = " edition software may not be used for commercial, non-profit, o" fullword ascii
    $s2 = "xes and expenses. You agree that you have not relied on" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}