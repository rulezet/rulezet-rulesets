rule Virus_Hijack_GenPack_Backdoor_Hangup_B_449 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_449.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "441c2227b06524a7972889b33f57106fb68cbd5f441692df85c6cc28b3cdc936"

  strings:
    $s1 = "Mvthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}