rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_250_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_250_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6dc8a0788114abd41e2d87efa4a1cdc65a84e311f4679a52fed38cec16706a3"

  strings:
    $s1 = "lXU%teAn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}