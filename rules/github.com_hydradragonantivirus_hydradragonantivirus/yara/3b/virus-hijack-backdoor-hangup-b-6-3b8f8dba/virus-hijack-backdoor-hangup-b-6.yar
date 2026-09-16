rule Virus_Hijack_Backdoor_Hangup_B_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a641d439bebdc2b2a57a1ed59142f59ee644b6c1e2b6852a87ec0a000f859e1f"

  strings:
    $s1 = "kjTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}