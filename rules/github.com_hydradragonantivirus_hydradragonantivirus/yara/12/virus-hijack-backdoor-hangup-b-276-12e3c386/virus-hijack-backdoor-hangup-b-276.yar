rule Virus_Hijack_Backdoor_Hangup_B_276 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_276.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e024c5e6cdd962d1e7b18dad47eea5f41dad86a4ac4f8234aa6d9c5b0f82d79"

  strings:
    $s1 = "%A. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}