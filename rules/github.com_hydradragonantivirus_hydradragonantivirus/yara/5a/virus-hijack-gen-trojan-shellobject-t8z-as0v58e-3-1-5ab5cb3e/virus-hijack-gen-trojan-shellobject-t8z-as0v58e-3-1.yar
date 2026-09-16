rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aS0V58e_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aS0V58e_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "399b05c1ae43bd1f4eb1086b51677900bf73e8f0575259f9e12ce20cbc78cae5"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" s-Ref:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}