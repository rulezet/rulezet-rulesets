rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_3b2083afdb57_1037 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_3b2083afdb57ae7e611f6f42c6787c73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"

  strings:
    $s1  = "Rx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s2  = "DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(funct" ascii
    $s3  = "),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s4  = "turn \"FJs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s5  = "{return \"DWe\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s6  = " \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s7  = " fuck(){return \"Vf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"D" ascii
    $s8  = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retu" ascii
    $s9  = "fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s10 = "fuck(){return \"Jh\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IO" ascii
    $s11 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fu" ascii
    $s12 = "k(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";}" ascii
    $s13 = "turn \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s14 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(f" ascii
    $s15 = "\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s16 = "return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(" ascii
    $s17 = "\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function " ascii
    $s18 = "})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ai\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}