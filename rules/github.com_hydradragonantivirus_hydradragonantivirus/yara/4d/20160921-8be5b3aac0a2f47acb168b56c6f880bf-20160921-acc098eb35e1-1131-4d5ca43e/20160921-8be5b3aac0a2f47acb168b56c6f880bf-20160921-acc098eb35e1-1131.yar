rule _20160921_8be5b3aac0a2f47acb168b56c6f880bf_20160921_acc098eb35e1_1131 {
  meta:
    description = "datamaliciousorder - from files 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_acc098eb35e159f33783b155bb8929cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash2       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"

  strings:
    $s1  = "k(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";" ascii
    $s2  = "unction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){ret" ascii
    $s3  = "),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii
    $s4  = "\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s5  = " \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(fun" ascii
    $s6  = "ck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf" ascii
    $s7  = "n fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s8  = "function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s9  = "nction fuck(){return \"Tv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return" ascii
    $s10 = "uck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf" ascii
    $s11 = " fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"I" ascii
    $s12 = "o\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s13 = "k(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";}" ascii
    $s14 = "return \"Zy\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})()" ascii
    $s15 = "ction fuck(){return \"DWe\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retu" ascii
    $s16 = "ction fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){retur" ascii
    $s17 = "IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}