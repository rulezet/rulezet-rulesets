rule Virus_Hijack_Trojan_GenericKDZ_103285_874 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_874.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecfdd4e25d0d64ca1308bb0a78d36cbafc6ae6334aa67d1ee19213b6f1cf5baf"

  strings:
    $s1 = "Eavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}