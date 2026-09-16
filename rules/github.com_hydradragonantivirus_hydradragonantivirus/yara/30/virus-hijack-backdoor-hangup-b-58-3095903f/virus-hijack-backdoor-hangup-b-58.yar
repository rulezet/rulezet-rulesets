rule Virus_Hijack_Backdoor_Hangup_B_58 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_58.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "916c165e789b690a65758c1f5118044888b8eb624798857f5a985b6c53c4bf5d"

  strings:
    $s1 = "Dof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii
    $s2 = "\"jeRt#rKp#oD$.a^aJ2" fullword ascii
    $s3 = "JERm>PXk)eYwJ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}