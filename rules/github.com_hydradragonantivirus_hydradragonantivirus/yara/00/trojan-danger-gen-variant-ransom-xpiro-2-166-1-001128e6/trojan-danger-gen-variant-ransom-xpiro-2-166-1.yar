rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_166_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_166_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d30109cc20abf79d0e13b404726b5d7ad31574679849c02e8793a4855ad17d1"

  strings:
    $s1 = "#whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}