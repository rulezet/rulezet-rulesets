rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_209_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_209_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32fba6ff861d628e206b4c16fbaf2e9f77b2a857a34931342e96d7c6eba0f7cb"

  strings:
    $s1 = "`cdPhPerserdt^`psqftqpqtotfgpdc_oeogceb_bqgtbsbr`^qqsp`faro`^p`bdt^sd_PZP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}