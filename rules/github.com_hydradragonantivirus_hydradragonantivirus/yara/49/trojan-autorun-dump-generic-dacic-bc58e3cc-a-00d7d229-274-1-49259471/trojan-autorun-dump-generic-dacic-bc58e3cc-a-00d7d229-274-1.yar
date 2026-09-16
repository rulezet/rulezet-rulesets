rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_274_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_274_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f21c784e22f4f1ff64a0dca1daa525613cd62cbdb031e0fbffee4166489c67cc"

  strings:
    $s1 = "nLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}