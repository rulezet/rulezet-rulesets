rule Virus_Hijack_GenPack_Backdoor_Hangup_B_312_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_312_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0aa42db2fa7ea22795ca89d6f1149b4111240322dbf5ac248f73264e1a7c695c"

  strings:
    $s1 = "Evt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt" fullword ascii
    $s2 = "instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe" ascii
    $s3 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s4 = "instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}