rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_271 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_271.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecba6c3ba04e08bab5ad95100ed9b6f010dbf3f06a1c5f7a37b2977349f79fd7"

  strings:
    $s1 = "\"and services at the list price in effect at the " fullword ascii
    $s2 = "infringement claim could have been avoided by`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}