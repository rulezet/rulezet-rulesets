rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_1664afae3185_488 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_1664afae318573894e850f85ff412d64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"

  strings:
    $s1  = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){" ascii
    $s2  = "uck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh" ascii
    $s3  = "){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s4  = "ck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s5  = "rn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii
    $s6  = "uck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MOj" ascii
    $s7  = "ction fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){retu" ascii
    $s8  = "uck(){return \"Wo0\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IP" ascii
    $s9  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s10 = "uck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s11 = "eturn \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ar\";})()," ascii
    $s12 = "ction fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retu" ascii
    $s13 = "unction fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){retu" ascii
    $s14 = "{return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";}" ascii
    $s15 = "n \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"BGe\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s16 = ")(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"SUi\";})(),(function fuc" ascii
    $s17 = "k(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";}" ascii
    $s18 = "Il\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function" ascii
    $s19 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s20 = "Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}