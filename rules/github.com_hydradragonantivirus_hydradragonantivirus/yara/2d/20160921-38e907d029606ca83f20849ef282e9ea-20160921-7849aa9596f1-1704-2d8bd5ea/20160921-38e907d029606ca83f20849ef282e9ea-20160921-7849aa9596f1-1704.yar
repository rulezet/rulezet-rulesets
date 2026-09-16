rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_1704 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash4       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash5       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1  = "uck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"FJ" ascii
    $s2  = "n fuck(){return \"Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xw" ascii
    $s3  = "\"Xg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(functi" ascii
    $s4  = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s5  = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck()" ascii
    $s6  = "),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s7  = "urn \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s8  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(function f" ascii
    $s9  = "tion fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s10 = "rn \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s11 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"X" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}