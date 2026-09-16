rule _20160921_5f040a1454cafc62100cb4449da0b7e2_20160921_5fbbbcb8f403_433 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash2       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash3       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"

  strings:
    $s1  = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){r" ascii
    $s2  = "unction fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s3  = "})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s4  = "k(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\"" ascii
    $s5  = "ck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo" ascii
    $s6  = "nction fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retur" ascii
    $s7  = "})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s8  = "Pu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function" ascii
    $s9  = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s10 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retur" ascii
    $s11 = " fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s12 = "Kv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s13 = " fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RA" ascii
    $s14 = " fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s15 = "function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){ret" ascii
    $s16 = "s\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function" ascii
    $s17 = " fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IR" ascii
    $s18 = "turn \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s19 = "eturn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(" ascii
    $s20 = "\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}