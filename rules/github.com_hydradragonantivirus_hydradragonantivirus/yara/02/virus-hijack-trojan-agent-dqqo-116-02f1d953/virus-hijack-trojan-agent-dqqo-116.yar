rule Virus_Hijack_Trojan_Agent_DQQO_116 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_116.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a020a22f45cfb232848e1e7c7fe4082f71adb65af0610615edc01c841e1f88e6"

  strings:
    $s1 = "1norders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}