rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_74_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5187a5e8b9ddddc6c6cd959275f866a11774a534735e61baccb56867b9ae19b"

  strings:
    $s1 = "$IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}