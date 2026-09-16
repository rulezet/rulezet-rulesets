rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_683 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_683.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6489d17175e452cc9f41fabd3f95f31c78c766caf602f385ba19b42838f854ae"

  strings:
    $s1 = "kt<SOfT" fullword ascii
    $s2 = "$<LOfT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}