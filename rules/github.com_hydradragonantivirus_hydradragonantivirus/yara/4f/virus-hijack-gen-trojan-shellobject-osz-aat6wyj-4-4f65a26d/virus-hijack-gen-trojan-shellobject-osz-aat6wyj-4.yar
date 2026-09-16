rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ae510b412e50215903e0c0df1cd112d0371cf964cb9114b81af073f51bf8393"

  strings:
    $s1 = "71whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}