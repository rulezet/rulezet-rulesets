rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_77_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_77_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08fe2d383569b2b8ff8401427bfaa6c03f9bdaf68d6e287f4cf3731c14717f13"

  strings:
    $s1 = ".bdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}