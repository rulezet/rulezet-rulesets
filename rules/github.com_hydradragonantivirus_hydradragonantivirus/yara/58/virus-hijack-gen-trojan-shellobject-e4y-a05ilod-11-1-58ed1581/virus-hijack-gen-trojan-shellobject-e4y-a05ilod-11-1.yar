rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fde242c160942710f93fa933e3e84f1046d9ff3f218c895b2a02dff907769782"

  strings:
    $s1 = "AutoIt v3 Script: 3, 3, 8, 1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}