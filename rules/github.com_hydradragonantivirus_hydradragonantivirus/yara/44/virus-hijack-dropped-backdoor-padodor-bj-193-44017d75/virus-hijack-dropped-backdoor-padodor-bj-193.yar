rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_193 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_193.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f43995ad9ae526894a1130df445fd0b5e82084ce81862141c702e78a9410e96"

  strings:
    $s1 = "You may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}