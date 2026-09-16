rule _20160921_7f682825ca903be9931443996a6639e7_20160921_be4748da0160_783 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1  = "i\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s2  = ",(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){" ascii
    $s3  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs" ascii
    $s4  = "fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"D" ascii
    $s5  = "ion fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s6  = "ion fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s7  = "n fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s8  = "ck(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\"" ascii
    $s9  = "){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})" ascii
    $s10 = "o\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function" ascii
    $s11 = "n \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s12 = "return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"KVh\";})(" ascii
    $s13 = "fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve" ascii
    $s14 = "uck(){return \"Qh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr" ascii
    $s15 = "fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MO" ascii
    $s16 = ",(function fuck(){return \"Mw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s17 = "(){return \"YQt\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";" ascii
    $s18 = "Pu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"QTc\";})(),(functio" ascii
    $s19 = "){return \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ar\";})" ascii
    $s20 = ";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Np\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}