rule Virus_Hijack_Backdoor_Hangup_B_35 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51440476cfc0c1a56d7ea493b6e374ca0cf72e891c6584c79af6d6eddd179541"

  strings:
    $s1 = "WOTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}