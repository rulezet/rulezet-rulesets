rule Virus_Danger_Trojan_Agent_DQQO_23 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed2f720a32d6ceda38da682da041957b307bfae79abc8152979ef92dbf566839"

  strings:
    $s1 = "bfunctionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}