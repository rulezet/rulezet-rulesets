rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_50b14bf13c50_455 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_50b14bf13c50bc31f09e3c583e1d422d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"

  strings:
    $s1  = "return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s2  = "on fuck(){return \"SUi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3  = "\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function f" ascii
    $s4  = "eturn \"Yk\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Zy\";})(),(" ascii
    $s5  = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){retur" ascii
    $s6  = "){return \"Xw\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})()" ascii
    $s7  = "ck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xg\"" ascii
    $s8  = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s9  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(" ascii
    $s10 = "function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){ret" ascii
    $s11 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Nm\";})(),(" ascii
    $s12 = "\"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo\";})(),(funct" ascii
    $s13 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"" ascii
    $s14 = "unction fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retu" ascii
    $s15 = "\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function " ascii
    $s16 = "turn \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s17 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ug" ascii
    $s18 = "ction fuck(){return \"Py\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s19 = "eturn \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s20 = "n \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}