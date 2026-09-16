rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62587a426d1afd79111f2cd1d427d28a3024170f4fd352490330d6589d91229d"

  strings:
    $s1 = "1are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}