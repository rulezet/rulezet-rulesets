rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4879ab3dfa950c5e5f7cd15360fdf7d20e2da527d338f151ee242b9bd9236312"

  strings:
    $s1 = "Jwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}