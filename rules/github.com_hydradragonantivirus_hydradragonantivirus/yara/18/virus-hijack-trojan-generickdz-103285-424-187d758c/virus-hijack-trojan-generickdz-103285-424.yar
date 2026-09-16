rule Virus_Hijack_Trojan_GenericKDZ_103285_424 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_424.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ce3e0092fdcfc45adaf0191380b7523659bbb275d1a6fd9193ed1ce626a7ae9"

  strings:
    $s1 = "TWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}