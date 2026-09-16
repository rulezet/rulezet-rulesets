rule Virus_Hijack_Trojan_Agent_DQQO_138_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_138_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12d0a9857abc7fc22b309efe9ee62d3a26842ff52b51ad098e7438a66b946ad3"

  strings:
    $s1 = "5:THoB" fullword ascii
    $s2 = ")xyst>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}