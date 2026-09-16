rule Virus_Hijack_Trojan_GenericKDZ_98388_234_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_234_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78b81ad91bd9701d2508773b94f7ff0db6ce20f131644a248c67362aaf58226a"

  strings:
    $s1 = "SUwe@fj" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}