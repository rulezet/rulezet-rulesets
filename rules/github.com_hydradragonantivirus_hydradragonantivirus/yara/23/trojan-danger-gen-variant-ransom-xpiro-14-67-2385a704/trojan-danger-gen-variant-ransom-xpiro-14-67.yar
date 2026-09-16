rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_67 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_67.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e72b4a85d31a352c98eb91e14052d494385e163110b85a63949521c14c133b54"

  strings:
    $s1 = "V[TRap?<RRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}