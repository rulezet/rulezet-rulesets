rule Virus_Hijack_Backdoor_Hangup_B_294 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_294.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe289c8aaa7b54d4a9103c4fd77aa8fdf8d938d350e10610197e2bca7a80b9fd"

  strings:
    $s1 = ")/Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}