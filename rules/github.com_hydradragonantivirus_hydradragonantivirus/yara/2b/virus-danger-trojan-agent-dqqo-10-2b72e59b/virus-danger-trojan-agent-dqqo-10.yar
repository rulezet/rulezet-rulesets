rule Virus_Danger_Trojan_Agent_DQQO_10 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3392f15e0890362a3881ee30716f3b2bd335f763bb2425cc4dcd12dfdebe23c8"

  strings:
    $s1 = "):whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}