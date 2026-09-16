rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_707_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_707_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b23f4ec964b067ffdc722ac78036d8d84f83ebf1ad29998c0ff6fdab089ea755"

  strings:
    $s1 = "&^Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}