rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_530_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_530_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2807055a899e836d42b6c6f1286c22296cd2ca5877da504c91f3720ce420983"

  strings:
    $s1 = "TOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}