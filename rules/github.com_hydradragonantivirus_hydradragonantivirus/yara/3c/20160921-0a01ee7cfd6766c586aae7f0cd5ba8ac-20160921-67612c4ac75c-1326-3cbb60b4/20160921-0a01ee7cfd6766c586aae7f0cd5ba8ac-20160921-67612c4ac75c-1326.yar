rule _20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac_20160921_67612c4ac75c_1326 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash2       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"

  strings:
    $s1  = "on fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s2  = "nction fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retu" ascii
    $s3  = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retur" ascii
    $s4  = "urn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(f" ascii
    $s5  = "{return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";}" ascii
    $s6  = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";}" ascii
    $s7  = "uck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq" ascii
    $s8  = "n fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s9  = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){retu" ascii
    $s10 = "ion fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s11 = "urn \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s12 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s13 = "unction fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){re" ascii
    $s14 = "{return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";}" ascii
    $s15 = "){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}