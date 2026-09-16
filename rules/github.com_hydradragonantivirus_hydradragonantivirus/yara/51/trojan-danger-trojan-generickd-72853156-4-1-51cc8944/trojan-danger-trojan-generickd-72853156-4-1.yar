rule Trojan_Danger_Trojan_GenericKD_72853156_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff95375f6b7977c9a6e465b6845f356cb6801e2affd5f78569342dbaf77c2c5a"

  strings:
    $s1 = "REFUSE" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}