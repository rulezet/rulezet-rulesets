rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_666 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_666.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23f0f9b4d329e52da637cef30f104adbd47496936698cfb23ce393b0d6b988d"

  strings:
    $s1 = "|iLearning Subscription: is defined as a web base" fullword ascii
    $s2 = "T(tern" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}