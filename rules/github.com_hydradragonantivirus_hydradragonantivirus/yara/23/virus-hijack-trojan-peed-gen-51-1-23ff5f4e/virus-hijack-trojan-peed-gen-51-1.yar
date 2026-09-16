rule Virus_Hijack_Trojan_Peed_Gen_51_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58e9f0d261d9455da4e62e91cb3ee2c665bbc0d0604160dd611fcbf59319ac9a"

  strings:
    $s1 = "%KalE#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}