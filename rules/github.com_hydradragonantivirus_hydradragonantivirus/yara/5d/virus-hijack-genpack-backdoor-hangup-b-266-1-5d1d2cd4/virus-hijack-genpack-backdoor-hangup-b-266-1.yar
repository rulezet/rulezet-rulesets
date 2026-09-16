rule Virus_Hijack_GenPack_Backdoor_Hangup_B_266_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_266_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60689f3c41a6932e2c5b330678b1f8008aae2c4fbb6277e6edf805b10def50e7"

  strings:
    $s1 = "8:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:inst" ascii
    $s2 = "Evt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"" fullword ascii
    $s3 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s4 = "> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}