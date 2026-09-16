rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_169 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_169.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34350ed44c8170b5a138ffeaec9653e07b48af7c8c2f1c6869de14898e56deef"

  strings:
    $s1 = "3#Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}