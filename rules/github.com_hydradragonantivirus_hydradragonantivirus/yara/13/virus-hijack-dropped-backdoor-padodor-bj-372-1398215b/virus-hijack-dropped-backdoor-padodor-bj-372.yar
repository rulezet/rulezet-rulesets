rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_372 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_372.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff780912e3dc1b91acd62707e70683bf2747a3c23cdc675e23a17575ed7abf47"

  strings:
    $s1 = "iYou may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}