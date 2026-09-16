rule Virus_Sysbot_Gen_Variant_Pykspa_1_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Pykspa.1_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3e124d55b3f9fa54a0b77636aaf19551c194e3478851a76e4067c7e44b94714"

  strings:
    $s1 = "?juNk@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}