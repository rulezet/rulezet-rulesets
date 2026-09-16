rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_693_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_693_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f3b1fa8f0e264a39ef1e5df4f144c5dd5d7dbd5a41c266a88b95ee64133cade"

  strings:
    $s1 = "3counted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}