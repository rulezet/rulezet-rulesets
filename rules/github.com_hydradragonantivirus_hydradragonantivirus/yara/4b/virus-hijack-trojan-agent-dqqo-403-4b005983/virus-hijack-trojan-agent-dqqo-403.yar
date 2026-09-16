rule Virus_Hijack_Trojan_Agent_DQQO_403 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_403.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afaae6d914cbb0ec649b1750f0220f85ac08a9ea972c2b58b84b6a71cb6152df"

  strings:
    $s1 = "orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}