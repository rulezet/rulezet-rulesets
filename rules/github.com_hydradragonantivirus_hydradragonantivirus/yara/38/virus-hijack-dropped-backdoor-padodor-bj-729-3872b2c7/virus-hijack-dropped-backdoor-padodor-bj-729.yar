rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_729 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_729.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3b3f3b84d77c83f96e6f4423ab476bb6f04435311b8fe30755d301a8cf28cd1"

  strings:
    $s1 = ".prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}