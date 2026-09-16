rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_78_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "feeba69a75387d2ce792fcc6f77327746b43b767dbff4216fd77bc084bb55a9a"

  strings:
    $s1 = "AgOg T" fullword ascii
    $s2 = "and software vendors, so that they can use the information to i`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}