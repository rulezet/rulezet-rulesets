rule Trojan_Danger_Trojan_GenericKD_72304918_121_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa178069f5d00532f779db69c124d2a89de0dbee437bc6a943dfe77a7b3afd4a"

  strings:
    $s1 = "cvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}