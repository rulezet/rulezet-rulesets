rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e4ea387152ae223a91a86c20d5632c347cc3bbdc91ab1309a805aa9f0db668d"

  strings:
    $s1 = ") NudE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}