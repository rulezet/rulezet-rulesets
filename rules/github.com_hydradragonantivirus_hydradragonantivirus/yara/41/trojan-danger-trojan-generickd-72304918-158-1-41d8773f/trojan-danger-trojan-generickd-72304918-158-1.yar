rule Trojan_Danger_Trojan_GenericKD_72304918_158_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_158_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354e81763f2eaeecd4de4a6e8e6808b24d09ab7febb55dd39e7537fa747a3e8d"

  strings:
    $s1 = "4purchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}