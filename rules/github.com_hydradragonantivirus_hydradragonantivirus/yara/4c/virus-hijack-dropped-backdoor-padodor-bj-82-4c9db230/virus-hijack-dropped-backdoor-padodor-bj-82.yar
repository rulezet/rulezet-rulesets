rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_82 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_82.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60ee26b1abd7d1e3b04d11b84a6899f24166596f86e87eef036ac67905b0b844"

  strings:
    $s1 = "sOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}