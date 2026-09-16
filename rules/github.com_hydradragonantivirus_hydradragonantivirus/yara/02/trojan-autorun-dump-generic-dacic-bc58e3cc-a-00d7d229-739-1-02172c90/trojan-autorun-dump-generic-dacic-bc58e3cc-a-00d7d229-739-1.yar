rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_739_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_739_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e87178fd0182839192d6947804b47e4b5e8fc3ec2037384761547755af923a31"

  strings:
    $s1 = "have been paid. You should review the policies prior to`" fullword ascii
    $s2 = "-!A. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}