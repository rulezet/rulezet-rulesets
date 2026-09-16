rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_505_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_505_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6268c5a8ba057df34d4b78e65e9c8db73b603118f4c3422a3d4576e1e294b857"

  strings:
    $s1 = "#must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}