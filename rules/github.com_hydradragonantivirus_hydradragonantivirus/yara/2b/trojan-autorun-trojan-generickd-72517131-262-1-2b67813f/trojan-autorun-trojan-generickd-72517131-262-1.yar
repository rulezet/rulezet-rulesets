rule Trojan_Autorun_Trojan_GenericKD_72517131_262_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_262_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dece8a4b98aca4fa7a3401fd7c3238d74459138b9243a2725b42dd5c14ea6d63"

  strings:
    $s1 = "H9by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}