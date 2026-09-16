rule Trojan_Danger_Trojan_GenericKD_67166905_378_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_378_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7d44fe25c8c6d1c011daed46dd4798baf4bad0f32e0092bab755d5dc0063fb2"

  strings:
    $s1 = "user minimum table in the licensing rules section" fullword ascii
    $s2 = "shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}