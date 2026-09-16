rule Virus_Hijack_Trojan_GenericKDZ_103285_65_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_65_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9abeeabb9629af5d66534bd76ab4be86cb79cccc5176f5571107a35aa065acf0"

  strings:
    $s1 = "t:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li st" fullword ascii
    $s2 = "8 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from image/png to image/jpeg\"/> <rdf:" ascii
    $s3 = "gent=\"Adobe Photoshop CC 20" fullword ascii
    $s4 = "8 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from image/png to image/jpeg\"/> <rdf:" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}