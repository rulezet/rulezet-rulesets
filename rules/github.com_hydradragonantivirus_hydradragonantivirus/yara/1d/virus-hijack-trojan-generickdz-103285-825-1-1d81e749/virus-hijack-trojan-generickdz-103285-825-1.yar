rule Virus_Hijack_Trojan_GenericKDZ_103285_825_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_825_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b526089b34caf9d77dde6cdedc83ba15264b56a53347800eaeecfbfc6e595e19"

  strings:
    $s1 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdfAli stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii
    $s2 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdfAli stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}