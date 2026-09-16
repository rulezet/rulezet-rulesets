rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6b80f1626017a47b257f69053d1faac499f5c2f666dccc40578954110a8a5ca"

  strings:
    $s1 = "Welcome to use storm ddos" fullword ascii
    $s2 = "Storm ddos Server" fullword ascii
    $s3 = "Program Files\\Internet Explorer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}