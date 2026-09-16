rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_45_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97c1532e1da255b9aff7cacca6f4bf3ef6bcd195c3672adfa9a1c624bc3da279"

  strings:
    $s1 = "s@magE" fullword ascii
    $s2 = "bs@PagE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}