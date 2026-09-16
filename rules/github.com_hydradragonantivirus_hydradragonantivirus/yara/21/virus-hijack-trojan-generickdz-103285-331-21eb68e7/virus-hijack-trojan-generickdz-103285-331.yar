rule Virus_Hijack_Trojan_GenericKDZ_103285_331 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_331.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fab8ea09eaec6768e284bf6690c7da48d677e7458bfac79979732cf05fa58ff"

  strings:
    $s1 = "NWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}