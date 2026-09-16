rule Virus_Hijack_Trojan_Agent_DQQO_270 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_270.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbd08e5c34eb18194e2ef8eb85f0e04ca758cb9e5d79e0addd2c7c0f05a70522"

  strings:
    $s1 = "eEIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}