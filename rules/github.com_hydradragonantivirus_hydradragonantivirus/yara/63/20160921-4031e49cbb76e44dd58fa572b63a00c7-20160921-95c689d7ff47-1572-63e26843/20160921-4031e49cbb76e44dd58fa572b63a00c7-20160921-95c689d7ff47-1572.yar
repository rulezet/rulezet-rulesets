rule _20160921_4031e49cbb76e44dd58fa572b63a00c7_20160921_95c689d7ff47_1572 {
  meta:
    description = "datamaliciousorder - from files 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash2       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"

  strings:
    $s1  = "rn \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s2  = "n \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3  = "(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){r" ascii
    $s4  = "k\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function" ascii
    $s5  = "uck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np" ascii
    $s6  = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ug\";})" ascii
    $s7  = "ck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt" ascii
    $s8  = "n fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"U" ascii
    $s9  = "Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s10 = "on fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s11 = "n \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(fu" ascii
    $s12 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}