rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOIIYRj_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOIIYRj_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d34a32b1c044553ab8b803f4370526f7a73d1cb519adcaec91b2c10efaa556b3"

  strings:
    $x1 = "C:\\Users\\almhma\\Desktop\\Vb.neT ProjecT\\Service Network Windows\\Service Network Windows\\obj\\Debug\\Windows Defander.pdb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}