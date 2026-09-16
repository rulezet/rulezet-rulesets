rule Virus_Sysbot_Gen_Variant_Pykspa_1_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Pykspa.1_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a65836a44c27fbe6d0a55a89ab3a3f9aa1e2f9ee547435a4569fa8f3e420fd6e"

  strings:
    $s1 = "Mi}BOAr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}