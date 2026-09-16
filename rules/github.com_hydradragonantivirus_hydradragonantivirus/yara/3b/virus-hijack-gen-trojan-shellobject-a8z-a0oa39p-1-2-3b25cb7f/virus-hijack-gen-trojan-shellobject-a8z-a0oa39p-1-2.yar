rule Virus_Hijack_Gen_Trojan_ShellObject_A8Z_a0oa39p_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.A8Z@a0oa39p_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "779078a2b8de247c34688b4a4f368838b51425c658d5975ba465e2fd0b670548"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273cX-3fa6" ascii
    $s2 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273cX-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}