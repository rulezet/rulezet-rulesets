rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a077c3ccd90722e52ddbf1e7ff988e52864138f1fbeb65a284befb92ae9eb7f"

  strings:
    $s1 = "Host@FA" fullword ascii
    $s2 = "5Request rejected because SOCKS server cannot connect.QRequest rejected because the client program and identd report different u" wide
    $s3 = "Exception j@" fullword ascii
    $s4 = "Server@rB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}