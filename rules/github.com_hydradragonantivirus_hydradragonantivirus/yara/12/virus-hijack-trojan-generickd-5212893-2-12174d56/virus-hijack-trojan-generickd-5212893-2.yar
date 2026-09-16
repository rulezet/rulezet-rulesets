rule Virus_Hijack_Trojan_GenericKD_5212893_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKD.5212893_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29ad95e72664c4952771b18e1d4f1eda1b7ca4b4cf5d561857650c91b3b0cc1"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s2 = "d=\"/\"/> <rdf:li stEvt:action=\"save" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}