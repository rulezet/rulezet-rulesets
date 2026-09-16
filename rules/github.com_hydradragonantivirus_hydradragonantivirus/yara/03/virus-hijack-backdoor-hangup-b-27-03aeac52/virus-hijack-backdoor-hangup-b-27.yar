rule Virus_Hijack_Backdoor_Hangup_B_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "749c44dca44a989b851b72c2be2bbbf7101875dfe60f7fca9a5e538d73a40bff"

  strings:
    $s1 = "][Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}