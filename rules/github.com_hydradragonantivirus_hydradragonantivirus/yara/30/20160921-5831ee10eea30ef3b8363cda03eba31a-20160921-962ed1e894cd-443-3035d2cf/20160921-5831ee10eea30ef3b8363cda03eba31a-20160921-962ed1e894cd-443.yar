rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_962ed1e894cd_443 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_962ed1e894cd91f421ad984310ce3140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"

  strings:
    $s1  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s2  = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){r" ascii
    $s3  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return" ascii
    $s4  = "ion fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return" ascii
    $s5  = "ck(){return \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\"" ascii
    $s6  = "uck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"USf" ascii
    $s7  = "\"Zy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})(),(funct" ascii
    $s8  = "ck(){return \"Ai\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";" ascii
    $s9  = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck" ascii
    $s10 = "k(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\"" ascii
    $s11 = "function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){r" ascii
    $s12 = "urn \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s13 = "),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){r" ascii
    $s14 = "{return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s15 = "(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj\";" ascii
    $s16 = "Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s17 = "{return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo0\";}" ascii
    $s18 = ",(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){r" ascii
    $s19 = "eturn \"DRx\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"USf\";})()," ascii
    $s20 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Jh" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}