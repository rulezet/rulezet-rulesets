rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_70fc4d2c06ba_4949 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash3       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash4       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash5       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"
    hash6       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = "fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm" ascii
    $s2 = "urn \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s3 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(" ascii
    $s4 = "turn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s5 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"XFd\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}