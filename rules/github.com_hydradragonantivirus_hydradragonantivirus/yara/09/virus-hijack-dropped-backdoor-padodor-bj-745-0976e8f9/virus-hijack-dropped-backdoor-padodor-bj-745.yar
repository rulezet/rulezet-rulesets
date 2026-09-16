rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_745 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_745.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82a4b26ba5bc052161b4d65458cfe688df1267f974347b04e859df84a9135e23"

  strings:
    $s1 = "/]iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}