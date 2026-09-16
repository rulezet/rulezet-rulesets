rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_38e907d02960_4410 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash3       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash4       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash5       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1 = ")(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(" ascii
    $s2 = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){retu" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Np\";})()" ascii
    $s4 = "Bg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Py\";})(),(function" ascii
    $s5 = "){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}