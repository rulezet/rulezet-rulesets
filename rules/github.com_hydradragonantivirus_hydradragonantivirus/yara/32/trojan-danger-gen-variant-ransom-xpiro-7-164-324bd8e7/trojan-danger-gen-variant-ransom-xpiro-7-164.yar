rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_164 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_164.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e63cd5fd69dcb02aa50bcb75ad7d6c681467693318cb00009f8a8979a90d5829"

  strings:
    $s1 = ",What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}