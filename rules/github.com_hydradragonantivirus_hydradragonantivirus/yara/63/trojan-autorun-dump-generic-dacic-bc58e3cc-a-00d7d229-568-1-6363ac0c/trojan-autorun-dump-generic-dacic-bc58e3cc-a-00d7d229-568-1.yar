rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_568_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_568_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ba69313dcae8dccddcdf912a5f2bf7fd2744931bf401e60a275506dc0bc8784"

  strings:
    $s1 = "y|Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}