rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_651_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_651_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cba0ddf85a82b37683cc6e08f63462741156a8616bab30b83e4029d4aab3fbb0"

  strings:
    $s1 = "BIon!V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}