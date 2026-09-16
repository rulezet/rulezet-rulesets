rule Virus_Hijack_Trojan_GenericKDZ_74550_358_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_358_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2982b1e717adba6cb58d2697492a6f43f3b601b44d5a96f8507ca85230f4846c"

  strings:
    $s1 = "NEte$I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}