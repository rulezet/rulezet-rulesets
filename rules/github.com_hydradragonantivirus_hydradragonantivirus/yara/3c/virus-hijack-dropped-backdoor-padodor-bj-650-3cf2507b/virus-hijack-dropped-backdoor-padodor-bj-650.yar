rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_650 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_650.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b192a9db43926ef4a6a72a807d0d5e133895ddbf322361a329cac26eeb20f3d2"

  strings:
    $s1 = ",are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}