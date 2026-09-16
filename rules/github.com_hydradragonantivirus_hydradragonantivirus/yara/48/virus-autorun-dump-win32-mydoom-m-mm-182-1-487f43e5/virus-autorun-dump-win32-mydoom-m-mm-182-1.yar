rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_182_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_182_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72dfc2c0a05e72164f63e468bcc336cea2c25549ecc3a51cdc2c59979494529b"

  strings:
    $s1 = "H?F@HATE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}