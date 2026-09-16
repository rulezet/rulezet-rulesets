rule Virus_Hijack_Trojan_Agent_DQQO_261 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_261.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e710db4f313217a20ada24d0537bbe01eb433ff06ef25d937e92b96eb6cf41f"

  strings:
    $s1 = "IIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}