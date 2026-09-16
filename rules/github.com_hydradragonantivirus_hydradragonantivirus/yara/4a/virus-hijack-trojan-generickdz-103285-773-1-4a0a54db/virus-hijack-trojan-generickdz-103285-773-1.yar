rule Virus_Hijack_Trojan_GenericKDZ_103285_773_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_773_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0802480c0f4342d2967ae70609cc3d11daba7d2a517294c1a90c5731b9aadd8a"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s2 = "d=\"/\"/> <rdf:li stEvt:action=\"save" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}