rule Virus_Hijack_GenPack_Backdoor_Hangup_B_217_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee1fbf0b8852734ee63e852f6c3ce641688e6217f4a0cf4f4578582e66bf79a9"

  strings:
    $s1 = "o image/jpeg\"/> <rdf:li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li st" fullword ascii
    $s2 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}