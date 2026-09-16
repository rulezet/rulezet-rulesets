rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_33_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e15b6c43c2557cb0d554f77ce08e96ace0fab54e878599a0e0bf4022bc0db27"

  strings:
    $s1 = "The software also is not licensed for commercial hosting. For more information on multiple user scenariosa952fc166c78a9c32206993" ascii
    $s2 = "The software also is not licensed for commercial hosting. For more information on multiple user scenariosa952fc166c78a9c32206993" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}