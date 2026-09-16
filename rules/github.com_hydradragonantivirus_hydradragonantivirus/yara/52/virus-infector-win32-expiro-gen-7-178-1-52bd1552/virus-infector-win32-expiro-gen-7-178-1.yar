rule Virus_Infector_Win32_Expiro_Gen_7_178_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_178_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "deb0544db04e00ef38797b26a9db3a3308355624df761a043df060afd487c6ed"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}