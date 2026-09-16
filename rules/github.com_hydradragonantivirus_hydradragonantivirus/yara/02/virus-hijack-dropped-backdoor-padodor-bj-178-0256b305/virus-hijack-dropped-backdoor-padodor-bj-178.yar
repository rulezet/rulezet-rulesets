rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_178 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_178.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1337f7ed391f325b1374ed144eb2940befd1bc35c887a39c98fa1fb51f39c41c"

  strings:
    $s1 = "+and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}