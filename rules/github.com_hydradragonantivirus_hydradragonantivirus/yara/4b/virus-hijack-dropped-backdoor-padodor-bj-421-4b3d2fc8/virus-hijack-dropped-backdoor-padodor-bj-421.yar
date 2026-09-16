rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_421 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_421.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a6c50b99159fc5022497e16197a61210a1b739e083fdd975e69d1cd7fb5e060"

  strings:
    $s1 = "+and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}