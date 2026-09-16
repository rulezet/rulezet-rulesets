rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_628_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_628_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aa4617d78e3ef4aa48a621e2cff0e2b045c1b96025fa3888ac855a031c4b9c8"

  strings:
    $s1 = "'Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}