rule Trojan_Autorun_Trojan_GenericKDZ_94847_89_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_89_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ec46b6ea8215d70faf013871ffce3a1d27476d7c2ccf658dd6a5c243c31c190"

  strings:
    $s1 = "DYeR(-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}