rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_450 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_450.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4113d07a57b9c97e2eda757114e05ac8a3612e0a13bd2ab461717873051ca509"

  strings:
    $s1 = "9,are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}