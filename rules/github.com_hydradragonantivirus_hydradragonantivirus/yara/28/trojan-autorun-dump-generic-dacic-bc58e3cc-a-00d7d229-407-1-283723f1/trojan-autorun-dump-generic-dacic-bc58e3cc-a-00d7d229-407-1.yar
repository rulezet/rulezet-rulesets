rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_407_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_407_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c33f2307fced3078ad8f3640168efbc226ad7438dce3875de9335b5f88b988b"

  strings:
    $s1 = "1Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}