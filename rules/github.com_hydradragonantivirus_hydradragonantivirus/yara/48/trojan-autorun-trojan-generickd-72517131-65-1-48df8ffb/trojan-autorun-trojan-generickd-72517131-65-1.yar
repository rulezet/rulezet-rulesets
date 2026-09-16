rule Trojan_Autorun_Trojan_GenericKD_72517131_65_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_65_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d50e199a1551be555237c1f486735a260ed1963d80a03213b2099c4b4ba0079"

  strings:
    $s1 = "w4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}