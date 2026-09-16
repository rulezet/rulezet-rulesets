rule Virus_Danger_Gen_Trojan_ShellObject_g4Y_aqH1LVc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g4Y@aqH1LVc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd0abecd6092e0b000f5535fe997b7add71360adc00e03b757ed592e3a862402"

  strings:
    $s1 = "Microsoft Office PowerPoint 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}