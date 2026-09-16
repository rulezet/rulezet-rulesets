rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cf9ce9f060e90e2e24c0c36a403aea16439153c16d5e88d59e1f58f3d01aa5e"

  strings:
    $s1 = "!xwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}