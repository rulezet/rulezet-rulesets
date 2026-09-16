rule Virus_Hijack_Backdoor_Hangup_B_71 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_71.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad2706b8b55f5386fb0a8701d317148298209208834935097b079709dc565bfe"

  strings:
    $s1 = "Qof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}