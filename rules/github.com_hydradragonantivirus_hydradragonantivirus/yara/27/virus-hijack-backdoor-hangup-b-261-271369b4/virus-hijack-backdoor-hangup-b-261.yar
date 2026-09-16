rule Virus_Hijack_Backdoor_Hangup_B_261 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_261.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9897fc3bc8ee82ed751bc369f7933cfd3f02410e2360aa8650fb6d89e27850f7"

  strings:
    $s1 = "athe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}