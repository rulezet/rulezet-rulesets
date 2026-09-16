rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_b0c04db09e98_524 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash4       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1  = "ck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp" ascii
    $s2  = "eturn \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s3  = "uck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq" ascii
    $s4  = "\"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ai\";})(),(func" ascii
    $s5  = "rn \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(fun" ascii
    $s6  = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s7  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return" ascii
    $s8  = "nction fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s9  = "Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s10 = "fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NK" ascii
    $s11 = "tion fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return" ascii
    $s12 = "urn \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s13 = "\"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(func" ascii
    $s14 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s15 = "uck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\"" ascii
    $s16 = "fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii
    $s17 = "v\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"SUi\";})(),(function" ascii
    $s18 = "eturn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";})()," ascii
    $s19 = "nction fuck(){return \"Et\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retur" ascii
    $s20 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}