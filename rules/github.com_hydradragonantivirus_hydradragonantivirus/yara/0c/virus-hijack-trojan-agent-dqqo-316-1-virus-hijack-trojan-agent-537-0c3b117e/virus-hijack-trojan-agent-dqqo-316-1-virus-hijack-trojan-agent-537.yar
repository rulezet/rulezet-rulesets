rule _Virus_Hijack_Trojan_Agent_DQQO_316_1_Virus_Hijack_Trojan_Agent__537 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.Agent.DQQO_316_1.vir, Virus.Hijack_Trojan.Agent.DQQO_54_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_159_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_271_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_303_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_314_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_335_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_6_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_809_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf155b8f0cbb3668ca26a29287cc8470ab4592514a70b86519d33fe5d2308708"
    hash2       = "7c556929f5786bd43913f57a574db9cdbe864b5040a176ca80b6b6b27eaa17ce"
    hash3       = "d51d816882b1583eedcffcee78dcf70dd7d7e1476c8a330795416aa64331ea30"
    hash4       = "fd4f91526adedd755131816a12c4bd9fdd9901f9b85d513b997f8a25aa3b5bbc"
    hash5       = "191507f56721309c2b9043661dc9d7e08250cbbafeea9063d346662a73cf8c0e"
    hash6       = "2cdeb047b38849c9ad9903a1987069a697ab6e2757289dadd29fd3468c4178e1"
    hash7       = "3a6213830f87fc599ef556e435af3d5ffc6f31f4b765a85c7a090a59765a110f"
    hash8       = "aca0ac5703ea2b1f9aac9555d36b7bfa41e8d15979c6cd5b93ec1c78c8ad1f1b"
    hash9       = "62f1eeb10f257a35e5c7b1be969a02fc8114d84facdba6dbe0bdea22c01c6285"

  strings:
    $s1 = "\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf" ascii
    $s2 = "ceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393ca" ascii
    $s3 = "\" xmpMM:OriginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"c" ascii
    $s4 = "Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c6656" ascii
    $s5 = "ceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393ca" ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}