rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_121_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c993584afec232b69f609bbd39d68a292d2cc6004ca6fbee6607d48be58f96ec"

  strings:
    $s1 = "Twhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}