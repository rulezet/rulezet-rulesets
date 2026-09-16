rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_318 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_318.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc8d49156923ccc4002babb1d9ea572db04988fe1cade24aafce70b30c29bcff"

  strings:
    $s1 = "xare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}