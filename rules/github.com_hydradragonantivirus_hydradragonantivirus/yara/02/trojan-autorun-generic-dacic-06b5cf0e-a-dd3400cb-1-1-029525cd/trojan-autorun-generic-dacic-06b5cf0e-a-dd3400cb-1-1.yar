rule Trojan_Autorun_Generic_Dacic_06B5CF0E_A_DD3400CB_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.06B5CF0E.A.DD3400CB_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a1bc3c83f6661559454e2654e3d74c69b81e8cd1155303fd160522a33c7f30e"

  strings:
    $s1 = "phundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}