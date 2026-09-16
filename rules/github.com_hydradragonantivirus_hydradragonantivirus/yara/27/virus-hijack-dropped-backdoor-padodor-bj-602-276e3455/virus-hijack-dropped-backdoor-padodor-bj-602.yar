rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_602 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_602.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d24ca24f8193ddddc2e4e7a866de294d769a276fe010bc9bb4f01e6a56468c0f"

  strings:
    $s1 = "Snare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}