rule Virus_Hijack_Trojan_GenericKDZ_74550_277_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_277_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0bd75d8f8f92b9387045d21d4755908ec309fb8bc24dc7211d569cbef403e8e"

  strings:
    $s1 = "4 Raad" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}