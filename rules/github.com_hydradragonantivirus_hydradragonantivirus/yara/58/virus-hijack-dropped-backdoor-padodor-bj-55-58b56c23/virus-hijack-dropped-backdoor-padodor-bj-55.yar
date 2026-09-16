rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_55 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82db5ad2713d16677abd6af3f7919a0a809568cd1009a39ec01b761d4da7ab21"

  strings:
    $s1 = "<gRUE!" fullword ascii
    $s2 = "<gRUE!E1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}