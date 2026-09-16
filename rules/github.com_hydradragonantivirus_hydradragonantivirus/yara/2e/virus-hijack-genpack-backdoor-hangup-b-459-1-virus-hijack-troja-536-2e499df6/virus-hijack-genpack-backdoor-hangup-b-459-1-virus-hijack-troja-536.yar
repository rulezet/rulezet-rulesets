import "pe"
rule _Virus_Hijack_GenPack_Backdoor_Hangup_B_459_1_Virus_Hijack_Troja_536 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_GenPack.Backdoor.Hangup.B_459_1.vir, Virus.Hijack_Trojan.Agent.DQQO_228_1.vir, Virus.Hijack_Trojan.Agent.DQQO_364_1.vir, Virus.Hijack_Trojan.Agent.DQQO_398_1.vir, Virus.Hijack_Trojan.Agent.DQRC_1_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_115_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_131_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_164_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_195_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_482_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354dbc8bc80d6c03cfd506f0bb646742c799059944a3727b1fdaa0619f4a9257"
    hash2       = "f26ab08190926a79a5d7fea21beaf76dc75214e33998fdd509ac4e714fad1a36"
    hash3       = "1fe5fb08193ed99c677097f1bd63ad4f8098703d1eb883e166c942798c951bbf"
    hash4       = "875dd07bf73963909c12233db88d5676b20f0eb251e55a60c9f92cf9ee02c603"
    hash5       = "a083591c17bce38ef0846ba85c9dea74eb225ed52f00eb82ebfedec3001f0de3"
    hash6       = "9996c01051dba03b706453199ea1a9b7ea24e7969c7753a19692832e788c6af8"
    hash7       = "c65d165f14f9a8cbb23f32063720018f9fd132b8b860bca526a23be581aac38f"
    hash8       = "fddfcc53d32694c704f348a04710da0142426d9c4b0b3c60e1fae1b635848bfc"
    hash9       = "b8094379f95e951dc92abe006ede1f6c4249d41af3608b459b6e0ff7e3a62f08"
    hash10      = "3a57dbfc330c08d151fb9cf842bf02c2354cc8a1591c8263584b1c2616ff1f7b"

  strings:
    $s1 = "65623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"" ascii
    $s2 = "Agent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-" ascii
    $s3 = ":InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9b" ascii
    $s4 = ":InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9b" ascii
    $s5 = "93cacbc\" xmpMM:OriginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:act" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e" and (all of them)
    ) or (all of them)
}