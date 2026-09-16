rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_337 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_337.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "254227722470c46eba8fd97009df97e4004c9ec6b09a1b590b1ffd6b96b600a4"

  strings:
    $s1 = "=active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}