rule Trojan_Autorun_Trojan_GenericKD_72935145 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72935145.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a93fdf4da1be42280c50efdf0ca5548382879d66fb67344a4f87fe311910222d"

  strings:
    $s1 = "]Visible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "[::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}