rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_49 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19f8e3d330a1b9e6235d747c2bd817282892d67ea0e2559c603ab4b0a026fe67"

  strings:
    $s1 = "yare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}