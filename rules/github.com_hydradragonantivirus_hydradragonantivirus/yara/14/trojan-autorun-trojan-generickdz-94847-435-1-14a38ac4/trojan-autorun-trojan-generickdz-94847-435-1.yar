rule Trojan_Autorun_Trojan_GenericKDZ_94847_435_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_435_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3076d4376f5abd2940c87a18c35a43fd3daf396cb53110b57aec9aba9f59f8a9"

  strings:
    $s1 = "breaching party continues reasonable efforts to cure the breach. You agree that if you " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}