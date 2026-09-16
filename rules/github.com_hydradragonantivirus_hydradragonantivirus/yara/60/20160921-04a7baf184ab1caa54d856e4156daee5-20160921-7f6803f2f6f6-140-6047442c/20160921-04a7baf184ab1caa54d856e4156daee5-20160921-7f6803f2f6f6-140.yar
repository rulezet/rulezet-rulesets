rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_7f6803f2f6f6_140 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"

  strings:
    $s1  = "rn \"AUx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s2  = "on fuck(){return \"ZWu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return " ascii
    $s3  = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4  = "nction fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s5  = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"M" ascii
    $s6  = " \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s7  = "{return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(" ascii
    $s8  = "\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})(),(function " ascii
    $s9  = "ion fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s10 = "){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";}" ascii
    $s11 = "fuck(){return \"ZWu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"E" ascii
    $s12 = "fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm" ascii
    $s13 = "n \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s14 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Ot\";})(),(funct" ascii
    $s15 = "),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s16 = "unction fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retur" ascii
    $s17 = "eturn \"Av\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})()" ascii
    $s18 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YAv\";})(),(function" ascii
    $s19 = "),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s20 = "(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}