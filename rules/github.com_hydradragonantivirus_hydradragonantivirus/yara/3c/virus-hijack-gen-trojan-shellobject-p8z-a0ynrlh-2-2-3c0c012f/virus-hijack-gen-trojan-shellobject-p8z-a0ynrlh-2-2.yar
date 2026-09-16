rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_a0YNrLh_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@a0YNrLh_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f24164fbe10dba12464f60f59b5f0baa827d3ec64a2c7c0c6736fbd1a8b51044"

  strings:
    $s1 = "^Visible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "[::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}