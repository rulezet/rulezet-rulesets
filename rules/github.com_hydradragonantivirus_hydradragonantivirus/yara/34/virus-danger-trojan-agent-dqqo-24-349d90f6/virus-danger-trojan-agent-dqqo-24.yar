rule Virus_Danger_Trojan_Agent_DQQO_24 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e218c024227cf2468572889072bd85e0a4a4336b3737ea0f4221e8653d78d568"

  strings:
    $s1 = ",automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}