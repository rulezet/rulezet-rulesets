rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_481_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_481_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a2d4d3311452f221f8723edf768b899d51f517c44bd6ad47d8cd2553a3eab36"

  strings:
    $s1 = "?Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}