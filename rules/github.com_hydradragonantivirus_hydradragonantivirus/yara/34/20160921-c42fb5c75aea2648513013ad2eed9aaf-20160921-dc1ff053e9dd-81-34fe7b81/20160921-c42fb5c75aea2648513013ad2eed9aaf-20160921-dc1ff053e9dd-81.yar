rule _20160921_c42fb5c75aea2648513013ad2eed9aaf_20160921_dc1ff053e9dd_81 {
  meta:
    description = "datamaliciousorder - from files 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash2       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1  = "on fuck(){return \"Wo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"I" ascii
    $s2  = "k(){return \"Ai\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\"" ascii
    $s3  = "fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s4  = "ck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm" ascii
    $s5  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return " ascii
    $s6  = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retur" ascii
    $s7  = "\"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(functi" ascii
    $s8  = "n fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NK" ascii
    $s9  = "\"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s10 = "fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IR" ascii
    $s11 = "){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";" ascii
    $s12 = "eturn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})()," ascii
    $s13 = "tion fuck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s14 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return " ascii
    $s15 = "ck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo" ascii
    $s16 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(" ascii
    $s17 = "urn \"Xw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s18 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii
    $s19 = "fuck(){return \"Ai\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s20 = "ck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}