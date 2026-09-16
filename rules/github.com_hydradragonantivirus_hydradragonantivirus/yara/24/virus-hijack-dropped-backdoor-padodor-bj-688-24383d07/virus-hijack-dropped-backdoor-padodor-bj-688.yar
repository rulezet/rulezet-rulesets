rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_688 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_688.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4251aaae3759fb912725fb43702d4233fbf4c17488aff04350659c8e3068ed7"

  strings:
    $s1 = "Pare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}