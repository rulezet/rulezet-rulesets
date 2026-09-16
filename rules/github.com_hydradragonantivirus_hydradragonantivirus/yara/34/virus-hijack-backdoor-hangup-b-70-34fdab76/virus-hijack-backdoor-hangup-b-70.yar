rule Virus_Hijack_Backdoor_Hangup_B_70 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_70.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26ec4d830d0a9bb447638f5929e481f09443fb89eaeacd9ac3c657cc88d0b107"

  strings:
    $s1 = "Pcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}