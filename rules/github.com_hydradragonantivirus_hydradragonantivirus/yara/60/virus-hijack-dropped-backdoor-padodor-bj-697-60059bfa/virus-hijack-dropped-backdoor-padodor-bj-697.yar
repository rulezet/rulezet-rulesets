rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_697 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_697.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a09ac60e437e4720511ef53efa61a297f16ea16cb470f8dd7b0dcce7c541a8a"

  strings:
    $s1 = "s policies regarding financing which " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}