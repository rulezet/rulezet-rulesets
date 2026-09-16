rule Virus_Hijack_Trojan_GenericKDZ_103285_509_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_509_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9fe36c9e227a9f9099a7f917c29da45892cb9ecd2c430e1b658158e3bda6899"

  strings:
    $s1 = "6-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\"  tEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:c" ascii
    $s2 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}