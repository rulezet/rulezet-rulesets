rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_69_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5be397a8b1c80d070a34a5d1473489f9ce6859be9c6812dc06f6cb230a3e17e2"

  strings:
    $s1 = "prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}