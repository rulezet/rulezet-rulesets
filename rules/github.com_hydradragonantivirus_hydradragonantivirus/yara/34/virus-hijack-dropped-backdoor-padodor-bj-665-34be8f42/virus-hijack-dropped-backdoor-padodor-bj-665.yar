rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_665 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_665.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf59e4decdd4b6315e36498eace00055c40c760d7a86542cfe98bc26641c352f"

  strings:
    $s1 = "riLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}