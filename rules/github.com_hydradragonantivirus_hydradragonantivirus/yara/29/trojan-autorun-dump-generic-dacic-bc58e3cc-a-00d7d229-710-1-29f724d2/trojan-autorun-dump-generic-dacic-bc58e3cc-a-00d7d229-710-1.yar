rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_710_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_710_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "203fa2df4fd90ad225a4d7ae08bd0d40b66f3e36ed4148339cf33adf17af5ac4"

  strings:
    $s1 = "7kyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}