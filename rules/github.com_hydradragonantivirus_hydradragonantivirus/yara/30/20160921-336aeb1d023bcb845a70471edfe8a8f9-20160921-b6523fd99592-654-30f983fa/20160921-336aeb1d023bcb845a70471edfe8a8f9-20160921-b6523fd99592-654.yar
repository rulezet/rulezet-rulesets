rule _20160921_336aeb1d023bcb845a70471edfe8a8f9_20160921_b6523fd99592_654 {
  meta:
    description = "datamaliciousorder - from files 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash2       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"

  strings:
    $s1  = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(fu" ascii
    $s2  = "ion fuck(){return \"Cd\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s3  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){ret" ascii
    $s4  = "return \"Yk\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Np\";})()," ascii
    $s5  = "),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s6  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ot\"" ascii
    $s7  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii
    $s8  = "){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";}" ascii
    $s9  = ";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fu" ascii
    $s10 = "nction fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s11 = "eturn \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s12 = "return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(" ascii
    $s13 = " fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo" ascii
    $s14 = "\"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(funct" ascii
    $s15 = "o\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s16 = "})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s17 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(funct" ascii
    $s18 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UO" ascii
    $s19 = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retu" ascii
    $s20 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}