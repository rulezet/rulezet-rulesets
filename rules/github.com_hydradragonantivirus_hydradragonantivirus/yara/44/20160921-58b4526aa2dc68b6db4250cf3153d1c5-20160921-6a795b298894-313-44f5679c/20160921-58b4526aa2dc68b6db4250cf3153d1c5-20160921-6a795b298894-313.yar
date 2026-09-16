rule _20160921_58b4526aa2dc68b6db4250cf3153d1c5_20160921_6a795b298894_313 {
  meta:
    description = "datamaliciousorder - from files 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_7e2de7c26f136a1a958818752613cac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash2       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash3       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"

  strings:
    $s1  = "uck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn" ascii
    $s2  = "tion fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s3  = "uck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NK" ascii
    $s4  = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s5  = " \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s6  = "{return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(" ascii
    $s7  = "urn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(f" ascii
    $s8  = "Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s9  = "\"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s10 = "Kv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii
    $s11 = "return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})()" ascii
    $s12 = "k(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\"" ascii
    $s13 = "\"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii
    $s14 = "function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){ret" ascii
    $s15 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s16 = "),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s17 = " fuck(){return \"TTs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"L" ascii
    $s18 = "{return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(" ascii
    $s19 = "ck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"USf" ascii
    $s20 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}