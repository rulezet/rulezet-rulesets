rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_67_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d59aa7ed8feb1ba76a2cdc0c65b6781484a44e03f20e06bb52dca6f5dad891c1"

  strings:
    $s1 = "wand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}