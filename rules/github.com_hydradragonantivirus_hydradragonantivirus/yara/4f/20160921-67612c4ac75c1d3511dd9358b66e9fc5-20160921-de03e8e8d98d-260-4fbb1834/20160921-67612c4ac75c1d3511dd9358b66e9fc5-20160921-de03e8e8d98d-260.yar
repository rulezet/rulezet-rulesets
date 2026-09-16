rule _20160921_67612c4ac75c1d3511dd9358b66e9fc5_20160921_de03e8e8d98d_260 {
  meta:
    description = "datamaliciousorder - from files 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash2       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"

  strings:
    $s1  = "n \"TTs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s2  = "})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Dc\";})(),(function fuc" ascii
    $s3  = "ck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs" ascii
    $s4  = "(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s5  = "{return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";}" ascii
    $s6  = "fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MO" ascii
    $s7  = "return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s8  = "k(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm" ascii
    $s9  = " \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s10 = "(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";" ascii
    $s11 = " fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii
    $s12 = "\"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s13 = "unction fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s14 = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function f" ascii
    $s15 = "urn \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s16 = "),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s17 = "unction fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s18 = "turn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})()" ascii
    $s19 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s20 = "n fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"C" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}