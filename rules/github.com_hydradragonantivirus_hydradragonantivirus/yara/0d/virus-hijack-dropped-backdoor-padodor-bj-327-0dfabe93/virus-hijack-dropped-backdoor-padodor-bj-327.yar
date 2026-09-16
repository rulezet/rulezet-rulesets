rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_327 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_327.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15f0a368bbf859718d20b7c3ba8178bc5d42ea1220b37c743a2360d578286beb"

  strings:
    $s1 = "<JIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}