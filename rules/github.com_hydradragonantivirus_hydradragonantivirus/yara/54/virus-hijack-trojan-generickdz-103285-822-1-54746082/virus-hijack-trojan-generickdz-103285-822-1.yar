rule Virus_Hijack_Trojan_GenericKDZ_103285_822_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_822_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eed364267a5ce6c94cef20e627f64fe99dce773c14c63bab0e5479ba80c1254d"

  strings:
    $s1 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdfAli stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii
    $s2 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdfAli stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}