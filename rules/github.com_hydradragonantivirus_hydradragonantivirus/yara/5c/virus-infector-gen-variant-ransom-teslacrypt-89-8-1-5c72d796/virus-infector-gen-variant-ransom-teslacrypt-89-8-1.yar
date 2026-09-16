rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_89_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.89_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf5764350714c009146f22389fb13010f038f241c9bffb9f2c72dc43186a3bda"

  strings:
    $s1 = "g Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference Viewi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}