rule Trojan_Danger_Trojan_GenericKD_72853156_607_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_607_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18cc272229301cedff111a8e5c8e067a3ee673089f05f29789187cc4f3240f4e"

  strings:
    $s1 = "Host@HA" fullword ascii
    $s2 = "Mode(&C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}