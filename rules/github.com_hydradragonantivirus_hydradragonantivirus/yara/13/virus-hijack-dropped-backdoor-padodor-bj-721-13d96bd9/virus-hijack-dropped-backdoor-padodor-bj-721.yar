rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_721 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_721.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2fb93f91557244c523b4f43bdb0ab4f7cef913d9121705b7c4d9453275228b5"

  strings:
    $s1 = "cOCO!AF" fullword ascii
    $s2 = "JLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}