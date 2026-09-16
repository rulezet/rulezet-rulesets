rule Virus_Infector_Generic_Dacic_F7D02F69_A_BBC5CED0_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Generic.Dacic.F7D02F69.A.BBC5CED0_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec34f53754a3d08f1ce98551647f143cf31fe828065cd10e8b1f338959e83a77"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}