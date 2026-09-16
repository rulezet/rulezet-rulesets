rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26052170a8cbac0f9e5ff7a00f7ec9c4ea251a7ebf0144c6214c125943b6ad71"

  strings:
    $s1 = "qMLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}