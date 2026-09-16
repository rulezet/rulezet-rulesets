rule Virus_Infector_Trojan_GenericKDZ_70400_2 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKDZ.70400_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98c8b8c51286467a617cf71ddfd150ec6afd1a44bbf7c3e7837b195d785083fe"

  strings:
    $s1 = "p.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                       " ascii
    $s2 = "42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=" ascii
    $s3 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s4 = "42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}