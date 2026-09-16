rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_2E81587A_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.2E81587A_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b5fc54e3dfa55aeea2678d28f1830dc02f9344c66c35e09a73cf19bae0e419"

  strings:
    $s1 = "Whundred euros) in all purchase orders transacted" fullword ascii
    $s2 = "f\"<scaN'g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}