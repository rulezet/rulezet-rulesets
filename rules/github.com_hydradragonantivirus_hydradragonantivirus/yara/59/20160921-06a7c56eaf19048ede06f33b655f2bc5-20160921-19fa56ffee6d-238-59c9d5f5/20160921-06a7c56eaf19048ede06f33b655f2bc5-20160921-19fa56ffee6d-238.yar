rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_19fa56ffee6d_238 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_9dc96613aa4c64f92e4ff218607f50d0.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js, 20160921_f575ae0885e764a3ea3a621283d492e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash3       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash4       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash5       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash6       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash7       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash8       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash9       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"
    hash10      = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash11      = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash12      = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash13      = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"
    hash14      = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"
    hash15      = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"

  strings:
    $s1  = "eturn \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(" ascii
    $s2  = "n \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(fu" ascii
    $s3  = "(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){" ascii
    $s4  = "Hj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s5  = "k(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s6  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IOs\";})(),(function fuck()" ascii
    $s7  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(function fuck" ascii
    $s8  = "n \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s9  = "rn \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s10 = "),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){r" ascii
    $s11 = "rn \"Qh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s12 = "urn \"Hs\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s13 = "n \"ZLd\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s14 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s15 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(fu" ascii
    $s16 = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(functi" ascii
    $s17 = "){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UXf\";}" ascii
    $s18 = "uck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Av" ascii
    $s19 = "turn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Fv\";})(),(f" ascii
    $s20 = "eturn \"ZLd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"GNm\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}