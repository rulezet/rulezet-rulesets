rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_395 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_395.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f876480dac985ee8e1f6eec33c64dc74db24cac47280238fd5ea478c2b03df15"

  strings:
    $s1 = "{Iare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}