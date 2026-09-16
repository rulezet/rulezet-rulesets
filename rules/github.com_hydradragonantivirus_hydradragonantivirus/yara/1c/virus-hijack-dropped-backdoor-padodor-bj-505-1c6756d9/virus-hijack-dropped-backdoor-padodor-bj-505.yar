rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_505 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_505.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d44b43761480d32bd69b5c84291d064d7a50312480f2a4112c21301c8329394"

  strings:
    $s1 = ":You may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}