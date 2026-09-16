rule Virus_Hijack_Trojan_Agent_DQQO_224 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_224.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "887b466562ac212da74e9e8255ff3bfbb6bb5e4b5431139de9e64e05afbe0c41"

  strings:
    $s1 = "Eyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii
    $s2 = "anSa,b[a" fullword ascii
    $s3 = "D\"SaMp" fullword ascii
    $s4 = "o;SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}