rule Trojan_Danger_Trojan_GenericKD_67269844_16_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c9b43bd146a29228bd4610d813cf805da4e00ee1b2f76229b8cb808dc2c7482"

  strings:
    $s1 = "Smicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}