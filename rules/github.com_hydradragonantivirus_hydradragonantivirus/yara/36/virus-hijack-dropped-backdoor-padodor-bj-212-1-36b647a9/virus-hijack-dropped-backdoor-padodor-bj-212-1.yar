rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_212_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_212_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85b0c9e95971000f3b0edde61b5bc9d8588a1f317f6e42dd9ba5e1b5aa5c7c45"

  strings:
    $s1 = "7-Zip 19.00 (x64) is uninstalled" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}