rule Trojan_Danger_Trojan_GenericKD_67166905_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9551153476f521bffe6ad5f48e2c1d0d8f3486628629e043a1fea9407de4446c"

  strings:
    $s1 = "_What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}