import "pe"
rule _Virus_Infector_Gen_Variant_Barys_343142_11_1_Virus_Infector_Win_501 {
  meta:
    description = "datamaliciousorder - from files Virus.Infector_Gen.Variant.Barys.343142_11_1.vir, Virus.Infector_Win32.Expiro.Gen.7_159_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "422d5e4f41b5779b6f4cb60b9544ecb4dc16219943a2b5e963a2d124554115e8"
    hash2       = "214fc5e32af8744451ec751e4c6b0f295f4040d8b1f77fb21fa295352a8618e3"

  strings:
    $s1 = "/photoshop/1.0/\" xmlns:xmpMM=\"http:/Ans.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/}ap/1.0/sType/ResourceEvent#" ascii
    $s2 = "d46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt" ascii
    $s3 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s4 = "stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-c" ascii
    $s5 = "i stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08" ascii
    $s6 = "nalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:" fullword ascii
    $s7 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "cf305f9303758e0aa5370a3c5eba0051" and (all of them)
    ) or (all of them)
}