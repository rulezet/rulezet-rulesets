import "pe"
rule _Virus_Infector_Trojan_GenericKD_33222094_27_1_Virus_Infector_Tr_557 {
  meta:
    description = "datamaliciousorder - from files Virus.Infector_Trojan.GenericKD.33222094_27_1.vir, Virus.Infector_Trojan.GenericKD.33222094_4_1.vir, Virus.Infector_Trojan.GenericKDZ.96072_10_1.vir, Virus.Infector_Trojan.GenericKDZ.96072_50.vir, Virus.Infector_Win32.Expiro.Gen.7_108_1.vir, Virus.Infector_Win32.Expiro.Gen.7_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9299cef062eddac878ea60f34bc5a88eac6b104bd8d0d08c73e5cafab841248a"
    hash2       = "0d366269eefe971f983475096c78e538b7ace4600ee742afcd94d1dda62c30a9"
    hash3       = "9eea6a084d80d41b09b4022bcc8eee1392ddf135a8696686510ba03b6ec580c2"
    hash4       = "18a1b46ab9b37b4a498084d85b4a74e34fa5b705eb6fd99c6f2a6dca60d07dbd"
    hash5       = "48cf758edccdf5a940accd4e1857f5e608940905ee62bc24bb7c39e29ee8bd17"
    hash6       = "9a01115efaddaa3f8f007aac6c23fe8807f49a177e0b774bd010228a1cd81b31"

  strings:
    $s1 = "reAgent=\"Adobe Photoshop CC 201" fullword ascii
    $s2 = " (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-" ascii
    $s3 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s4 = " (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-" ascii
    $s5 = "-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=\"xmp.d" ascii
    $s6 = "4317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                              " ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "bd4e06697f271b2703a6127aae97c787" and (all of them)
    ) or (all of them)
}