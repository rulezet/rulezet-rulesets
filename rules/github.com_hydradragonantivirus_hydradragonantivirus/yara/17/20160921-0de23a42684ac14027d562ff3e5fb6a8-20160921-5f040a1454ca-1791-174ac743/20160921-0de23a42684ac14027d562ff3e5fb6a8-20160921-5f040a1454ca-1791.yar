rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_5f040a1454ca_1791 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash3       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash4       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash5       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"

  strings:
    $s1  = "eturn \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(" ascii
    $s2  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii
    $s3  = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s4  = "\"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(funct" ascii
    $s5  = "m\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s6  = "ion fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s7  = "(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";}" ascii
    $s8  = "on fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s9  = "(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"EHo\";" ascii
    $s10 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}