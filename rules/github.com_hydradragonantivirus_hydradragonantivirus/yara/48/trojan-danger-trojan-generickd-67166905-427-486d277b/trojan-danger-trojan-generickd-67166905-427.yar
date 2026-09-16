rule Trojan_Danger_Trojan_GenericKD_67166905_427 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_427.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90e6f91009ef86af2ab8af5d728fc860451f1b0b822e524735686c77801753b9"

  strings:
    $s1 = "System Information.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}