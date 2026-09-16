rule Virus_Hijack_Trojan_GenericKDZ_103285_291_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_291_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6142fc3783b15358cc226b79fe3089100384005c1dc700e98712ba73a9d3edcc"

  strings:
    $s1 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}