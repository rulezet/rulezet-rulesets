rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_557 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_557.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9d6bbadbe524e874a11dfd4b936a94eba4849995bf9e63b3c4ec8260433be2a"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the limited warranty. To make a claim unde" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}