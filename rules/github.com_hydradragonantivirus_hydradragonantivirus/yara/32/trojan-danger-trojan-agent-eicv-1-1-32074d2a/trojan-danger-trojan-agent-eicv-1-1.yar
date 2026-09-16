rule Trojan_Danger_Trojan_Agent_EICV_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.EICV_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "685654d969f5cdcc3cc1d26c56e8381e940b66c7642765f117b7c5f3ace6d327"

  strings:
    $s1 = "o=must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}