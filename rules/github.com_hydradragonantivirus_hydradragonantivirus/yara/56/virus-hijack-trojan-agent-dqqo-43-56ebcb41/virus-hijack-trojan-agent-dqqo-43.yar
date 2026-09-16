rule Virus_Hijack_Trojan_Agent_DQQO_43 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_43.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adcc8857e07fd2bc12a15ae72aa4ccad4413a4bf7add4712fffe7d5448a118e4"

  strings:
    $s1 = "uSwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}