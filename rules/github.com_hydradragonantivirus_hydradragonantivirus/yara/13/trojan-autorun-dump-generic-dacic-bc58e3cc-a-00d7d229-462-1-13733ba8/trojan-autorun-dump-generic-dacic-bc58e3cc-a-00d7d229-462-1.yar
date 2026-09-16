rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_462_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_462_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1104794b5e22774c2f26e63cbb6a1fd6dec488500e3a2b98677e9a9cf407ffce"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}