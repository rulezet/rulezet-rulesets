rule Virus_Infector_Trojan_GenericKD_33222094_26_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKD.33222094_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ae3a0711a8330474e5c71505e7914c4795ca08d009d6459b336bc1c141e8451"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}