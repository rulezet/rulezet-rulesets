rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_548 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_548.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc6a63ca92f2e2edf3124ea832cb918455670a3e5149109843bedf365db0f0c6"

  strings:
    $s1 = "|active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}