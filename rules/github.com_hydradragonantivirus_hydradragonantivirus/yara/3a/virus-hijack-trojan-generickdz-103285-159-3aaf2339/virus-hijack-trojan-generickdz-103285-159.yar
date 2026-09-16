rule Virus_Hijack_Trojan_GenericKDZ_103285_159 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_159.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e20052053579e87c0c0d49ababbe981b09682204f1d19528d82eafcd896816a5"

  strings:
    $s1 = "rVWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}