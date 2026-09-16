rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_68_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43bb5e80d8ab8ae95c0da2063cba0a1595b8b84ec8c018cf504029acf2857099"

  strings:
    $s1 = "BIon!V" fullword ascii
    $s2 = "WOFT& p}y*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}