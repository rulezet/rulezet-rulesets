rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_218_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf19a934495e1bbd37089e8ad51ed084268ec6f884837d72684eb192feb5564c"

  strings:
    $s1 = "~Lorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}