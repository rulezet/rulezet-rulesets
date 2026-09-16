rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_7b23bcfdd128_1850 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash3       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"

  strings:
    $s1  = "ck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\"" ascii
    $s2  = "uck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj" ascii
    $s3  = "ck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj" ascii
    $s4  = "rn \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(f" ascii
    $s5  = "\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s6  = "uck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s7  = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s8  = "k(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";" ascii
    $s9  = "TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function" ascii
    $s10 = " \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}