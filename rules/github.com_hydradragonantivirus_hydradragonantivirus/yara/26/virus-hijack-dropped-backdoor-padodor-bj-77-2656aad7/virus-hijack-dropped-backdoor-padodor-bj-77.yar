rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_77 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_77.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aae17222777ca35c508527315d87454500bb004694044bf39f4754d3ddfc334"

  strings:
    $s1 = "{iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}