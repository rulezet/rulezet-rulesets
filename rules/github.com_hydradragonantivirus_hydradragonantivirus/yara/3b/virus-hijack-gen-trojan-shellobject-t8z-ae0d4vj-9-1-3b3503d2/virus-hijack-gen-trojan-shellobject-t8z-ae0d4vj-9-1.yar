rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7109ba7f1af2d5d7c7572d99bd36b974ef3de6614b04b37b6a96c8ba27241f6"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" s-Ref:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}