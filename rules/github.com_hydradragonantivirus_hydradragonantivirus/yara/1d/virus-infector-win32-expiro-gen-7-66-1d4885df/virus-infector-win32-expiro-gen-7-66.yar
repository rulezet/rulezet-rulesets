rule Virus_Infector_Win32_Expiro_Gen_7_66 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_66.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a03e8b3a6fa93ee23bfc10d6be9bc0e7b895d0af589bea6b982275d5d9d35b98"

  strings:
    $s1 = "heLE`r" fullword ascii
    $s2 = "c;}mAiL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}