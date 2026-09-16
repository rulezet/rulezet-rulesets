rule Virus_Hijack_Backdoor_Hangup_B_300_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_300_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc00bb2bdcf76e2789a58444d1ab1016e6824a9ad19976987605e21ab5e4abe"

  strings:
    $s1 = "7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}