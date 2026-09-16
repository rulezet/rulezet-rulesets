rule Trojan_Autorun_Trojan_GenericKDZ_94847_487_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_487_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8eda13c5c866bf47d98f57d66f0c66a1885623c6ac4635ac6dda11229738ddbe"

  strings:
    $s1 = "]Vwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}