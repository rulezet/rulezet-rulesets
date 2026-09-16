rule _20160921_72beed3cbd321b62d224a35a01639682_20160921_f1bb498dcbb1_83 {
  meta:
    description = "datamaliciousorder - from files 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash2       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "ck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu" ascii
    $s2  = "urn \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s3  = "),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s4  = "n fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s5  = "})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s6  = " \"Nm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s7  = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return" ascii
    $s8  = "ction fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retur" ascii
    $s9  = "),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(" ascii
    $s10 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Nm\";})(),(functio" ascii
    $s11 = "(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){r" ascii
    $s12 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s13 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s14 = "{return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";}" ascii
    $s15 = "on fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s16 = "ck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s17 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(" ascii
    $s18 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){ret" ascii
    $s19 = "s\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s20 = "s\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}