rule _20160921_3a888f864f15e69e777cbaaa06f962e5_20160921_c01f87df9de4_1395 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash2       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1  = "(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\"" ascii
    $s2  = "fuck(){return \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s3  = "Pu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s4  = "){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";}" ascii
    $s5  = "u\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s6  = "eturn \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s7  = "),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){" ascii
    $s8  = "n fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s9  = " \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s10 = "urn \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})()," ascii
    $s11 = "n fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s12 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function " ascii
    $s13 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZLd\";" ascii
    $s14 = "uck(){return \"TTs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IR" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}