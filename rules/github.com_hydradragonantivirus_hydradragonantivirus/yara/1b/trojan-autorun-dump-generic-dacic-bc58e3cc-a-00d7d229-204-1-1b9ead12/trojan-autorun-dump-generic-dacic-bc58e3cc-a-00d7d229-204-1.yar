rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_204_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_204_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6c6cfa5bf67e71c7a68c4ec42362a01e0f41151cec75ca79b33043a20ad4eae"

  strings:
    $s1 = "BF1dDK!yUFt*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}