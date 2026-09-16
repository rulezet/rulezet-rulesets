rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_db727bb0ba7a_716 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1  = "\"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s2  = "n \"KVh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3  = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"N" ascii
    $s4  = "rn \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(fu" ascii
    $s5  = "){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})" ascii
    $s6  = ")(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s7  = "return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(" ascii
    $s8  = "\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function f" ascii
    $s9  = ";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuc" ascii
    $s10 = "rn \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(f" ascii
    $s11 = "on fuck(){return \"PDf\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return " ascii
    $s12 = "urn \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s13 = "Pu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s14 = ")(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s15 = "})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function fuc" ascii
    $s16 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return " ascii
    $s17 = ";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuc" ascii
    $s18 = "g\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Dc\";})(),(function " ascii
    $s19 = "(){return \"Jo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Xg\";})" ascii
    $s20 = ",(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}