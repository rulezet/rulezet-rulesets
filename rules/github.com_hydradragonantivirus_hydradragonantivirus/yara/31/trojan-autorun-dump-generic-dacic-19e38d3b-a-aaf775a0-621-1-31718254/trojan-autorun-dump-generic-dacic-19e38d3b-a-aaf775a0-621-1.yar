rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_621_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_621_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dab71e0a6b577a25a4ebdefdcfd179e3b75b03ca90d0c08cbf240105e76c2e69"

  strings:
    $s1 = "SiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}