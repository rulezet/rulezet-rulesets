rule Virus_Autorun_Win32_Neshta_A_49 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d63c3717647483a95cd1b472d6a3b29a62ff006d40c028bae094c874e63b6157"

  strings:
    $x1 = "\\Device\\HarddiskVolume4\\Program Files\\Microsoft Office\\Updates\\Download\\PackageFiles\\F6198892-E306-45D9-8753-7F274254059" wide
    $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" fullword ascii
    $s3 = "edge://welcome/" fullword ascii
    $s4 = "edge://newtab/" fullword ascii
    $s5 = "SeAt#HRxu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}