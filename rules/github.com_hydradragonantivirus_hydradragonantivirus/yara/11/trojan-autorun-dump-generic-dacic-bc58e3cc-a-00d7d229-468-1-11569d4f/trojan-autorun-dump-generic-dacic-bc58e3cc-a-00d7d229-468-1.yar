rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_468_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_468_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd6bbc62857735d6cd06fb429307a408b5be7fa8d9ef078147825537a2b6513a"

  strings:
    $s1 = "bIprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}