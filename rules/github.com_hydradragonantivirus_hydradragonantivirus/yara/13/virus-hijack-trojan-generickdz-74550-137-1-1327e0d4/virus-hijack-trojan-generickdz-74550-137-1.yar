rule Virus_Hijack_Trojan_GenericKDZ_74550_137_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_137_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ed780752c22d169dcfa5b136bb0bc579f154c3631559e800c9d5e3cdc811096"

  strings:
    $s1 = "vila@B" fullword ascii
    $s2 = "te!Kung" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}