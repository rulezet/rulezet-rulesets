rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a2cf6379c670ac605996a4e768bb8c4272afa61d4252006995e411e9f6a8bb4"

  strings:
    $s1 = "ZYou may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}