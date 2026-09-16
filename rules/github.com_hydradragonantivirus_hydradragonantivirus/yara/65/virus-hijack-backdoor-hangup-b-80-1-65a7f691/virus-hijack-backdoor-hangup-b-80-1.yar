rule Virus_Hijack_Backdoor_Hangup_B_80_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_80_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "560666230ecd5fcdf5e6032bd2cdfe1272b80d0688b66ddc2886d5856c9362a2"

  strings:
    $s1 = "PHYSICAL;DR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}