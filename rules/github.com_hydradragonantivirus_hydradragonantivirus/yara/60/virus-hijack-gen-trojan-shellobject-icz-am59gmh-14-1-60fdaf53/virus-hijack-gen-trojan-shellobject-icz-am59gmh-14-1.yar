rule Virus_Hijack_Gen_Trojan_ShellObject_iCZ_am59Gmh_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iCZ@am59Gmh_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b80992ed3c96af46ebcc71d327e4dc5643ddfc1f5e4e4e4e0956caa8a72d217d"

  strings:
    $s1 = "!Error Download" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}