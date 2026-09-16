rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_8 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"

  strings:
    $s1  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"" ascii
    $s2  = "fuck(){return \"YQt\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s3  = "ck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"USf\"" ascii
    $s4  = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"ZLd\";})(),(fun" ascii
    $s5  = "),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(" ascii
    $s6  = "{return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})" ascii
    $s7  = "Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Mw\";})(),(function" ascii
    $s8  = "Sx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s9  = "unction fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s10 = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fu" ascii
    $s11 = ")(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s12 = " \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"FJs\";})(),(fun" ascii
    $s13 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"" ascii
    $s14 = "n \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s15 = "ction fuck(){return \"OQr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s16 = "\"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s17 = " \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s18 = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(" ascii
    $s19 = "ion fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s20 = "k(){return \"To\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}