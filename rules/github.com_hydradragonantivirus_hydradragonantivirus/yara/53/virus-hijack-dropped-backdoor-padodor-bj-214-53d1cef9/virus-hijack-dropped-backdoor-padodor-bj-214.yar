rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_214 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_214.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cf5358f0055f3e52166dd22702212a4726a28384ae9434cc16e776d736f7e4d"

  strings:
    $s1 = "WOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}