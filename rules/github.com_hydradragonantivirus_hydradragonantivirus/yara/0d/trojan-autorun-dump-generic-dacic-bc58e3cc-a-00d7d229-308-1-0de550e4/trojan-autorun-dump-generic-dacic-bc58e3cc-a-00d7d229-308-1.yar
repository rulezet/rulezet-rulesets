rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_308_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_308_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a217172a4a281fb6904377146d39df10fd23d31d1155297b03f74a75c2d3493"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}