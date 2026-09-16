rule Virus_Infector_Win32_Expiro_Gen_7_130_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_130_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59a69f2d51ba8c56fca243e800249d75d235f3ef58fbcf4503a5dde800361818"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:pHotoshop:953273c3-3fa6" ascii
    $s2 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:pHotoshop:953273c3-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}