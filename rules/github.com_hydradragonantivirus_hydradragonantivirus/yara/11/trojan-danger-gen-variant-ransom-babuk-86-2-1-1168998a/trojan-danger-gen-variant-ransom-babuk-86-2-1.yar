rule Trojan_Danger_Gen_Variant_Ransom_Babuk_86_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Babuk.86_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e248407e613a8a472ed54e0739b735717729323c58a82c8e56d50f508d4129f"

  strings:
    $s1 = "z9Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}