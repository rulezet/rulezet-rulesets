rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_543_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_543_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3afd9047dd7b5478f6bea52d7c0547170f832cecbe1916eb0c9feec85024b745"

  strings:
    $s1 = "J=University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}