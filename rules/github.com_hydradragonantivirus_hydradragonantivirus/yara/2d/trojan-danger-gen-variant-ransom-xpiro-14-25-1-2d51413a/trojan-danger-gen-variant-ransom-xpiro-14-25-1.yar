rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68485204d4d0f67dacb76dc29bf79eb4bf7fc1c6280260a2740b96fab2f5c3a3"

  strings:
    $s1 = "XOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}