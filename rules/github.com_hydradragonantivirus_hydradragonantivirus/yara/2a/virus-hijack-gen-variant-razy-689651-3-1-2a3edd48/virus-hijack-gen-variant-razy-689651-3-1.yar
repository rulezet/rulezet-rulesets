rule Virus_Hijack_Gen_Variant_Razy_689651_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Razy.689651_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac9d99b235a0fba3e49d8ab12967b12ffd611beaca85ffb8656596ad47e834b0"

  strings:
    $s1 = "/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.co{/xap/1.0/sType/ResourceEvent#" ascii
    $s2 = "oftwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-caee-fd4" ascii
    $s3 = ":action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" s" ascii
    $s4 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}