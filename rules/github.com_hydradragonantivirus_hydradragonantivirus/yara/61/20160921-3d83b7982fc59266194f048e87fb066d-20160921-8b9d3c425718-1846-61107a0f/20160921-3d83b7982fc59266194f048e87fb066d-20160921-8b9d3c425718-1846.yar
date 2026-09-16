rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_8b9d3c425718_1846 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_8b9d3c425718975422f8fe0d71119686.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"

  strings:
    $s1  = "Pu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s2  = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"CCb\";" ascii
    $s3  = "XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s4  = ",(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){" ascii
    $s5  = " \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(fun" ascii
    $s6  = "return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})()" ascii
    $s7  = "Rn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s8  = "unction fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){re" ascii
    $s9  = "unction fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){ret" ascii
    $s10 = " fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"N" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}