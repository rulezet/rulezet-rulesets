rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_782 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_782.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "523b6d64e6f9fc7556c019e3d2bff0b501ab50ad1db6527077a7faecf3fe9b0b"

  strings:
    $s1 = "1amust be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}