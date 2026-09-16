rule Virus_Hijack_Trojan_Agent_DQQO_317 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_317.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5a8b6711541e6480a1b76c221f5d88cbc470d7feb39a47262f728858795346d"

  strings:
    $s1 = "TELi;OAd1kAd1;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}