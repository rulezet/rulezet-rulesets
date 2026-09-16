rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_282_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_282_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "663337f5d1048a08a59da6ea29cdc289a0e8535e6a97812f9708ac16513daf8d"

  strings:
    $s1 = "user minimum tabl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}