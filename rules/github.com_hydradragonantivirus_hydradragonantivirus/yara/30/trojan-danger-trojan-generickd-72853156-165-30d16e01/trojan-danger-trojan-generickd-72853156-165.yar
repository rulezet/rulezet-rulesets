rule Trojan_Danger_Trojan_GenericKD_72853156_165 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_165.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "125c4e2ed46f0d80ea814a74da7fb8149ba2bba7cf7822ac9bfc250e18a19f7f"

  strings:
    $s1 = "Python Manuals.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}