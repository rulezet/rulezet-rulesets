rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_306_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_306_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "528532a8edc7f14cd6e8afabd082a7f7df75b6fe05bd3b2cd9eb0bf29ed48e6a"

  strings:
    $s1 = "vAgUS(^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}