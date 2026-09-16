rule Virus_Hijack_Trojan_EmotetU_Gen_nW0_h8lzSHmi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.nW0@h8lzSHmi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b332b02e3ff066970bda5077828eb66829bd325b756267090c8b6627a1684bf"

  strings:
    $s1 = "opacate" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}