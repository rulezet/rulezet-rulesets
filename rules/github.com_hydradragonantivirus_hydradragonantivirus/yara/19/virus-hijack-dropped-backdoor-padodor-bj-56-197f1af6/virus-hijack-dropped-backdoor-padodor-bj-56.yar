rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_56 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_56.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a4ac9abc777fadff8c97212aa1c4d9db90d8f295916e1254f3e36683ce1f7cd"

  strings:
    $s1 = " sLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}