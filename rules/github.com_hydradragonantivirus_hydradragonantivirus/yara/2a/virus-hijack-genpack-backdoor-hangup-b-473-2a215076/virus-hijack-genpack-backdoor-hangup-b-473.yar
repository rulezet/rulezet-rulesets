rule Virus_Hijack_GenPack_Backdoor_Hangup_B_473 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_473.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e34570f3969c33a5f9b32c1be832c62a7b2c3b42838c94e2936ad36833ae069"

  strings:
    $s1 = ">-of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}