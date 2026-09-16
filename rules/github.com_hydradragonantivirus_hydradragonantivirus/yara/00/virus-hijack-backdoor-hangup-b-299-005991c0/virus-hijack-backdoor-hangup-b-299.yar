rule Virus_Hijack_Backdoor_Hangup_B_299 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_299.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dc7278c73f9d05e577b4080a04e82326114de145cce7e5e13bee44d3ef412c0"

  strings:
    $s1 = "wthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}