rule Virus_Hijack_Gen_Trojan_ShellObject_S8Z_aeKx0jo_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.S8Z@aeKx0jo_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe9e2afbe37bda5820fad8fa5634933fff8d0cd44ab7b667d00890e787682a74"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = ":li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:" ascii
    $s3 = "p.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                       " ascii
    $s4 = "ceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photo" ascii
    $s5 = "CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-712" ascii
    $s6 = "42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=" ascii
    $s7 = ":li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}