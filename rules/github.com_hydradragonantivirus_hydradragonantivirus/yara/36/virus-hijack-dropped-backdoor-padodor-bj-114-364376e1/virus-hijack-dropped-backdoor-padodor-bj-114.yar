rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_114 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_114.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8725b9531048cedb4746a17dc139ea253914a1e04bd77381ba449aee4b92974d"

  strings:
    $s1 = "]Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}