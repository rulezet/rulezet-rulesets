rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_356_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_356_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "178de09b44dc35d73f132c7f9ace8bd2b688910da2d04f27f7e095ec38e3400c"

  strings:
    $s1 = "you to install only one copy of the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}