rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_526 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_526.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec7748b780ee203b9cdcb48cccf6e66c75f743759c96a50cce1026d5b30c42dc"

  strings:
    $s1 = "?If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}