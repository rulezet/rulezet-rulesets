rule Virus_Hijack_Trojan_GenericKDZ_74550_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22de018406045a2e65d7c67de21f62bbbf8b7fdcf5f1772eb6ca275f1960251e"

  strings:
    $s1 = "toXA@}0$cv" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}