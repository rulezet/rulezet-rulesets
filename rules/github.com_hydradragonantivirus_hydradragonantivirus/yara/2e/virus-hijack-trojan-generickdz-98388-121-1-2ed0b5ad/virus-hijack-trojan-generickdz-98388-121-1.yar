rule Virus_Hijack_Trojan_GenericKDZ_98388_121_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddce63d2933c4c87d7e40ab23f35ec43f4631176d703c90ffa53d4f05f111cb4"

  strings:
    $s1 = "d$ROde" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}