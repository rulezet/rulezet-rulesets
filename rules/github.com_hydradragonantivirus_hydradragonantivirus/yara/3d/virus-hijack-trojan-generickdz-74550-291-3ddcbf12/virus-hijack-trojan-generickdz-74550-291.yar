rule Virus_Hijack_Trojan_GenericKDZ_74550_291 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_291.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e04b2164c3541574107dd659beaa35ebc496557726f4bda88ff0faa25d89918"

  strings:
    $s1 = "jimP%i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}