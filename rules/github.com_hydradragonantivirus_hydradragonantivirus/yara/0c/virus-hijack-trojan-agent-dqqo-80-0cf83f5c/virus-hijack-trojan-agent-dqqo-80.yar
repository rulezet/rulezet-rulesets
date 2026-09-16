rule Virus_Hijack_Trojan_Agent_DQQO_80 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_80.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baad8378064a09b8c68ce71265fcaefeb664cd9ae9f9bd177dd8633edff54200"

  strings:
    $s1 = "@IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}