rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_511_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_511_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7226328a7cbb438967106420a913f22e37197ec02dfdce483b06f6700c7e6dd0"

  strings:
    $s1 = "VoAr:v2" fullword ascii
    $s2 = "waIN'e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}