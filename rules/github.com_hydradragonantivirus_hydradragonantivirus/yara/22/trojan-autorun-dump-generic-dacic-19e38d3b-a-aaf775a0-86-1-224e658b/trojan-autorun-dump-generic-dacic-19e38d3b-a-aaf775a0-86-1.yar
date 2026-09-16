rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_86_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c32dccc8eed7c3bb806243cfd5ad23041e7b0eb491a0bac75f647919d613fd72"

  strings:
    $s1 = "-!prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}