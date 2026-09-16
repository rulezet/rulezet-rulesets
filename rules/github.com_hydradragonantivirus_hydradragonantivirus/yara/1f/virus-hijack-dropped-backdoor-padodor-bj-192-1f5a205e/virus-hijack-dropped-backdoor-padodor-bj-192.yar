rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_192 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_192.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b6131ef976b3176d2abdfa2a5cf40cf5a7dae557d5c83b5088ff9ce9170bcee"

  strings:
    $s1 = "E:and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}