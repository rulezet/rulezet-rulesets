rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_291_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_291_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd907e766b0a1c91f86c668eb272f3ff0e7fbb74144f2b99b336de13e399efc2"

  strings:
    $s1 = "mwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}