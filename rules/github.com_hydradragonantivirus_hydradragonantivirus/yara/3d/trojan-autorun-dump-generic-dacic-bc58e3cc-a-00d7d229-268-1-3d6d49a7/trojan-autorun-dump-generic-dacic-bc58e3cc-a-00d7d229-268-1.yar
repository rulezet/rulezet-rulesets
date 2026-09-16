rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_268_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_268_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd9ae1732fc41e135a73d5c9b1d397f4b2c3e30bc1a175903a09836e372fc55"

  strings:
    $s1 = "user minimum tabl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}