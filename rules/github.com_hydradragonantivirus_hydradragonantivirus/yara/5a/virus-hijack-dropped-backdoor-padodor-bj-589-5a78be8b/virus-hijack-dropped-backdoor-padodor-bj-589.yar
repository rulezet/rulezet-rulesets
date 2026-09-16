rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_589 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_589.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d9d548e9db8c82d66d4e2747b673952c8cea16349d58310be2ccd4d82a09aeb"

  strings:
    $s1 = "Bactive employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}