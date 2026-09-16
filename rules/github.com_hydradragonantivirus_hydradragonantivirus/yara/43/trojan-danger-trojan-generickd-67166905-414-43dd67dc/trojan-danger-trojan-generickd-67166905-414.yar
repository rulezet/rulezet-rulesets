rule Trojan_Danger_Trojan_GenericKD_67166905_414 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_414.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8b2bcd3abe1e68710ac5cca5e6d950b5e62bafe342043102ea1eb9b1c5a82bd"

  strings:
    $s1 = "g]dhai]h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}