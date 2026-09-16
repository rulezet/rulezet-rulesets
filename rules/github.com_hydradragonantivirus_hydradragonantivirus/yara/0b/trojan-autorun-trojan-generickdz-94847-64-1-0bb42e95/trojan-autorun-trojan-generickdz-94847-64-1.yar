rule Trojan_Autorun_Trojan_GenericKDZ_94847_64_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2980f6c18991294f91fe13f5cc1cde70ab7dac7f39efdae6266a11aed450403"

  strings:
    $s1 = "breaching party continues reasonable efforts to cure the breach. You agree that if you " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}