rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_278 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_278.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1f071fdcf33c8c2f91cb7df342c99ed5fa3635d6ea022e1ac0bd7bcd27b25"

  strings:
    $s1 = " active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}