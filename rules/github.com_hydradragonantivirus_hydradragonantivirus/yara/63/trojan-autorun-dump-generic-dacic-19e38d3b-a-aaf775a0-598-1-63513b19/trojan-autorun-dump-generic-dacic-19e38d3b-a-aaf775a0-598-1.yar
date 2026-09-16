rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_598_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_598_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6752b0d8f40d0098883eccf74f44c1cc8281c235003da8150b1438c8f91276fb"

  strings:
    $s1 = "H)%shAN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}