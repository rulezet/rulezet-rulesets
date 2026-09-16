rule Virus_Hijack_Dropped_Win32_Worm_VB_NXJ_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c54bf7c91d4ea7217937635feb4dfa226e4678dc540b6120a6f8f7154b2454e0"

  strings:
    $s1 = "phototypist" fullword wide
    $s2 = "knopped" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}