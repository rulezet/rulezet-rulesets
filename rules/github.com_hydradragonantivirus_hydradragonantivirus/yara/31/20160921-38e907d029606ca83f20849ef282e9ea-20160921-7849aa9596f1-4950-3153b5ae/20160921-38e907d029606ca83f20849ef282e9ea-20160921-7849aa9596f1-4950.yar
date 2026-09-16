rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_4950 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash4       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"
    hash5       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retur" ascii
    $s2 = "){return \"Wo0\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})" ascii
    $s3 = "\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function f" ascii
    $s4 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s5 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}