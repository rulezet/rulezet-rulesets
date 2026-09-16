rule _Virus_Infector_Trojan_GenericKDZ_96072_12_1_Virus_Infector_Troj_539 {
  meta:
    description = "datamaliciousorder - from files Virus.Infector_Trojan.GenericKDZ.96072_12_1.vir, Virus.Infector_Trojan.GenericKDZ.96072_14_1.vir, Virus.Infector_Trojan.GenericKDZ.96072_47_1.vir, Virus.Infector_Win32.Expiro.Gen.7_104_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bc0617df53255237ead9ccf4d80c41e703f709acdfb716846dbaf36fc2d1050"
    hash2       = "d0e7906f7043ebc15e25e50a800c5ea87adf6e0edfd39095d228336e2d194b8b"
    hash3       = "b46c5658f734cae1d8c7a1724c974e09c492ae7dc4910243c2a306153e563cdd"
    hash4       = "18edfdfa6de1c3da9eaa2864a099d13373def44d04d54e9fbac3aa5e304908b9"

  strings:
    $s1 = "ftwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.ii" ascii
    $s2 = "8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li" ascii
    $s3 = "-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4" ascii
    $s4 = "-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4" ascii
    $s5 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}