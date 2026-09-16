rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_458 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_458.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c887cce059b7f0f4105c0d182df6305d041774fa546eb81841654b6e4e7ecde2"

  strings:
    $s1 = "5KLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}