rule _20160921_3b2083afdb57ae7e611f6f42c6787c73_20160921_b6523fd99592_226 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash2       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash3       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"

  strings:
    $s1  = "return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s2  = "nction fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s3  = "rn \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s4  = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"U" ascii
    $s5  = "unction fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){ret" ascii
    $s6  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retu" ascii
    $s7  = "return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})" ascii
    $s8  = "uck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn" ascii
    $s9  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii
    $s10 = "return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})" ascii
    $s11 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s12 = "Pu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s13 = "GWo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(functi" ascii
    $s14 = "n fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s15 = "n \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s16 = "function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii
    $s17 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s18 = "){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";" ascii
    $s19 = "rn \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s20 = "\"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}