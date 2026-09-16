rule Trojan_Danger_Trojan_GenericKD_67166905_471_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_471_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1252cf21c3914c26511e522a448156ecb3260bb1d39d8a8e9292d6b12f5891fa"

  strings:
    $s1 = "'}UDaL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}