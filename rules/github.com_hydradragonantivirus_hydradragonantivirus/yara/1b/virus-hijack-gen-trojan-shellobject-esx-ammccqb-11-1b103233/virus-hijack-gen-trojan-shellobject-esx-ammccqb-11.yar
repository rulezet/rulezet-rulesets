rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca2080105fc0fd5a8932d34bded9f032f0fb62f4d93f1bec7a71e5e403d59fdf"

  strings:
    $s1 = "rwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}