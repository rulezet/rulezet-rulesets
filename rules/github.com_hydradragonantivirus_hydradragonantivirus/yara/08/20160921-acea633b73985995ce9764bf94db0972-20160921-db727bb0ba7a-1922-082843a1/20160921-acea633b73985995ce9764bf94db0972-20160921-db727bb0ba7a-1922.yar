rule _20160921_acea633b73985995ce9764bf94db0972_20160921_db727bb0ba7a_1922 {
  meta:
    description = "datamaliciousorder - from files 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1  = "\"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii
    $s2  = "rn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(f" ascii
    $s3  = "{return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s4  = " fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"A" ascii
    $s5  = "Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s6  = "(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){r" ascii
    $s7  = "return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})" ascii
    $s8  = "Ts\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s9  = "on fuck(){return \"We\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s10 = "on fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}