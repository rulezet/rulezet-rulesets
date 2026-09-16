rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_404 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_404.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c69434b576985c93bd9b90bacf8e1829f28692515f669f0d9b5562171334cc1"

  strings:
    $s1 = "c0If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}