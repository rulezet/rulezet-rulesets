rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_140 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_140.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9af9a131eddaeb9a8f47cd83c1473e6b952985f4dc1579977b0eff999b058f6b"

  strings:
    $s1 = "OkMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}