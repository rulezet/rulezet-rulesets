rule Virus_Hijack_Trojan_Agent_DQQO_204 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_204.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "569b45edea5b55fd9bdb9fce7178161f3db29009228ce3585f3c3fa4a86b9339"

  strings:
    $s1 = "3OIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}