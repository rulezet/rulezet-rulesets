rule Virus_Hijack_Trojan_Agent_DQQO_338 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_338.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f27bad034888f5562341f571517eccb72c1ad0997161a92085d846cd29ac1441"

  strings:
    $s1 = "]*Toppy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}