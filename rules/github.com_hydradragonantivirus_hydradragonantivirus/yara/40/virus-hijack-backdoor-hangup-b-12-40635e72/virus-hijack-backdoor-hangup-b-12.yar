rule Virus_Hijack_Backdoor_Hangup_B_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36a4d3e6bda44a457ea82d7deb4bda18f99c6eea0baadbff4732e5e684ea0f53"

  strings:
    $s1 = ">Mthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}