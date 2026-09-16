rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_338 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_338.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92d592e4631ca52e216297d0100015e98b0020cebae52adc4d4e0e831ab544ef"

  strings:
    $s1 = "active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}