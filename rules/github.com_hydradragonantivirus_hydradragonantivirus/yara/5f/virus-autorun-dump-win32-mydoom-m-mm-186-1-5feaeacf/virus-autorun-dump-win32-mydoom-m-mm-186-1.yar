rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_186_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_186_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a20798e608cdcbeeb2760348619c8e96646d72090001c19386a46eb4965c77c"

  strings:
    $s1 = "Microsoft Office Publisher 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}