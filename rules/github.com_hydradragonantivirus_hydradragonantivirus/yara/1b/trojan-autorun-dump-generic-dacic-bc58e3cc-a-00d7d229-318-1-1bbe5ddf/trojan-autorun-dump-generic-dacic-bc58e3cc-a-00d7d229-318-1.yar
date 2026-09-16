rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_318_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_318_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2816fe1cdcd090cc84e3e21cffda5e1f8e090c6e6fd7cba2e83f5097275753"

  strings:
    $s1 = "/If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}