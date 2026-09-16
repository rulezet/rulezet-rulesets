rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_446_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_446_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4bce9c56b199b4ae5b6606689d51a474a916fa367be86a4294c9af6f922f4de"

  strings:
    $s1 = "Care a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}