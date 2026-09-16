rule Virus_Hijack_Trojan_Agent_DQQO_48 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_48.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5e556e5b03e75a5059aa1f3bf6db0e1c2c798f3b38ea4dcb094ac6360fc48da"

  strings:
    $s1 = "VMwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}