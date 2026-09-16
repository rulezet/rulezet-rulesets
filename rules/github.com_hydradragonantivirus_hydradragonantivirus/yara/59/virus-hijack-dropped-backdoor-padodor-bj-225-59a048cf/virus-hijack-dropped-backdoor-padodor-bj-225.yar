rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_225 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_225.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ee88b3aa0a19d203d51acd30079345fe50a1cd6dae3abd7c6461c523283af52"

  strings:
    $s1 = "z4are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}