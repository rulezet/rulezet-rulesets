rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_483 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_483.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f74e5b9153b8aeb8a27f7a1344b288eaf0e84994f5a85e371a8aac9901dd78a"

  strings:
    $s1 = "jpLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}