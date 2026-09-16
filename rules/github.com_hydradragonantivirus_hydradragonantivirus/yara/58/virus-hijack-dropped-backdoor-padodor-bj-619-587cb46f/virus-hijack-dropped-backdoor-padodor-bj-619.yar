rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_619 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_619.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c730a1b78ba281c82da0e8ce93e05feffbcf543bd9da7e8fb75a7b7737f0b2d9"

  strings:
    $s1 = "dare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}