rule _20160921_d56a785468c6ab02ba1f7ee3a5eadcdb_20160921_e354814fb086_869 {
  meta:
    description = "datamaliciousorder - from files 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"
    hash2       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"
    hash3       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1  = "\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function f" ascii
    $s2  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Zy\";})(),(function fuck" ascii
    $s3  = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function" ascii
    $s4  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"We\";})(),(function fuck(){retu" ascii
    $s5  = "fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Zy" ascii
    $s6  = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"GJx\";}" ascii
    $s7  = "n fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s8  = "n \"CCb\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s9  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){re" ascii
    $s10 = "){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(" ascii
    $s11 = "),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){" ascii
    $s12 = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})()," ascii
    $s13 = " \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii
    $s14 = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s15 = "eturn \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s16 = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){retur" ascii
    $s17 = "uck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"GN" ascii
    $s18 = "nction fuck(){return \"Pc\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii
    $s19 = "){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Cd\";})" ascii
    $s20 = "n \"Xw\";})(),(function fuck(){return \"VMi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}