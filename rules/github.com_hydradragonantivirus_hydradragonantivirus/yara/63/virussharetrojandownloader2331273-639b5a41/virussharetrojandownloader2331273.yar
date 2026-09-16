rule VirusShareTrojanDownLoader2331273 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader2331273.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbbfbc62e02e0054062d10cef49cbe8847211c6479ed1f08556bcbc3c347d4d"

  strings:
    $s1 = "copy SDForce.exe %systemroot%\\system32\\SDForce.exe" fullword ascii
    $s2 = "Shutdown -s -t: 0 -f" fullword ascii
    $s3 = "S&shift" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}