rule _20160921_31c7951a9301bccac7c42ed2b6b13093_20160921_8881f4de1f94_346 {
  meta:
    description = "datamaliciousorder - from files 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash2       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"

  strings:
    $s1  = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Zy\";})(),(func" ascii
    $s2  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){ret" ascii
    $s3  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Qh\"" ascii
    $s4  = "rn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(fun" ascii
    $s5  = "\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Xw\";})(),(function f" ascii
    $s6  = "eturn \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s7  = "{return \"DWe\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s8  = "return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Mw\";})(),(" ascii
    $s9  = "turn \"EHo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s10 = "),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s11 = "\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function f" ascii
    $s12 = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return" ascii
    $s13 = "ck(){return \"We\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\"" ascii
    $s14 = "urn \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(fu" ascii
    $s15 = "n \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s16 = "n \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s17 = " fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn" ascii
    $s18 = "n fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"" ascii
    $s19 = "Ot\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Zy\";})(),(functio" ascii
    $s20 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}