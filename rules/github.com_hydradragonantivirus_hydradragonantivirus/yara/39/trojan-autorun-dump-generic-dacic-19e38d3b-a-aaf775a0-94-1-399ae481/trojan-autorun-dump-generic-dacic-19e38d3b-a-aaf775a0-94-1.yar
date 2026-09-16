rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_94_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_94_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "865ff6237aa3633749360872065301104fcac247b2edd66f4cf1a8758dfab203"

  strings:
    $s1 = "w=iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}