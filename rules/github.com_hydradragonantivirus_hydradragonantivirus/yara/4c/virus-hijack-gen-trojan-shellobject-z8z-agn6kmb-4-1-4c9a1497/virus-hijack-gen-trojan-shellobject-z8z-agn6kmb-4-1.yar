rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aGN6KMb_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aGN6KMb_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "231a7d23c449cf4ab38cf89d9be8f2829b514ab6a63d6a65b83655dfa8754f61"

  strings:
    $s1 = "018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}