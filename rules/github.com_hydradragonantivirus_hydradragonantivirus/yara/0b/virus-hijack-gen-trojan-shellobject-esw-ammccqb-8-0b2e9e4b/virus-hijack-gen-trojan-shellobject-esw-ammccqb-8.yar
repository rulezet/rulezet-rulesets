rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d195e3c98f5afa3c1cfd48f4c2686ef0df63bca816004ff470586b64c34154f9"

  strings:
    $s1 = "rWwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}