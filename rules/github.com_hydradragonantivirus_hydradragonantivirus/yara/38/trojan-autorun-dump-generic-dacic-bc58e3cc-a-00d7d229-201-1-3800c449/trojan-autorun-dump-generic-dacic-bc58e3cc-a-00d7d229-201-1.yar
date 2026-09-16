rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_201_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_201_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e07877a9df748c9ade2ac2c18383a8bee011a2e86797d68e2c39d107f729674"

  strings:
    $s1 = "2Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}