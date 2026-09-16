rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_2884 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_c330005443bf481e5f5fac8acbb85145.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash4       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash5       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"
    hash6       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"

  strings:
    $s1 = "on fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s2 = " \"Cd\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3 = "eturn \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})()" ascii
    $s4 = "ck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){" ascii
    $s6 = "Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s7 = "){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"GNm\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}