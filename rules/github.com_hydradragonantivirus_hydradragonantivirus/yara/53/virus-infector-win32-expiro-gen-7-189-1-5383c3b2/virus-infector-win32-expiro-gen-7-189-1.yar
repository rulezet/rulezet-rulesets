rule Virus_Infector_Win32_Expiro_Gen_7_189_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_189_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86f58dbf77a2bb57d4b68cee4dd43f7735a83a2fbf7b2c4c7c776e12293a4e61"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}