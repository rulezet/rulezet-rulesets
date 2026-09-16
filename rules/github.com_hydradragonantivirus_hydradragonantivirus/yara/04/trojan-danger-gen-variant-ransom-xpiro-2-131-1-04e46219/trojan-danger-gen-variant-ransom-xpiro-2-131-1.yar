rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_131_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_131_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d92fac25d25edaaa345e01993b926327f5191b3c64a5d36a2cec987786d85fc"

  strings:
    $s1 = "_aOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}