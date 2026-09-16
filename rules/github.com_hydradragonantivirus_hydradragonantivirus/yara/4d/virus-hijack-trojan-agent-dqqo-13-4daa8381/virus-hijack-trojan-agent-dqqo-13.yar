rule Virus_Hijack_Trojan_Agent_DQQO_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aade85fc0f4be0a299c1ba5b1941fd3566d9bcd12dac46429124a3551b2dbf51"

  strings:
    $s1 = "dIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}