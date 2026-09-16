rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb8e4c950bd492d2311fa86af465122d673d77e55c462ee150dd3efabf3177cc"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide
    $s4 = "coRm[RV" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}