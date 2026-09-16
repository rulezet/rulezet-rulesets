rule Virus_Hijack_Trojan_GenericKDZ_103285_480_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_480_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6644950e4b33583fdd46285f61b838bdbd3d64c883c49324b396188dbdb915f9"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-580`-2842-91eb-924792347dc3\"" ascii
    $s3 = "890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                            " ascii
    $s4 = "890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                            " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}