rule Virus_Hijack_Trojan_GenericKDZ_103285_347 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_347.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41a535c27a59fe062042694d7b51ca847ee07ecf1dff5d78dcc625f45797fe9c"

  strings:
    $s1 = "Gavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}