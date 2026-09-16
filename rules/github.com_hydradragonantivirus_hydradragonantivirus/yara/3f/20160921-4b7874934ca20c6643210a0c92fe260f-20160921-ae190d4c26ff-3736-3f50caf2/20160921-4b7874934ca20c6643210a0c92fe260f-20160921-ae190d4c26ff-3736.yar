rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_ae190d4c26ff_3736 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"

  strings:
    $s1 = "){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";" ascii
    $s2 = "unction fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s3 = "(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii
    $s4 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s5 = ",(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s6 = "(),(function fuck(){return \"We\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}