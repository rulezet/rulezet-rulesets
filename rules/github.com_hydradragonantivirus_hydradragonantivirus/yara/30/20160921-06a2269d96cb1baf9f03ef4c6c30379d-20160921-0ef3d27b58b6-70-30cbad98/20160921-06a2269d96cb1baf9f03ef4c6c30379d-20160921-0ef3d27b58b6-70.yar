rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_70 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"

  strings:
    $s1  = "fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml" ascii
    $s2  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"UXf\";})(" ascii
    $s3  = "tion fuck(){return \"MIl\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s4  = "){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";}" ascii
    $s5  = "{return \"DHd\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Xw\";})" ascii
    $s6  = "){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s7  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){r" ascii
    $s8  = "(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";" ascii
    $s9  = "n \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(fu" ascii
    $s10 = "n fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s11 = "function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){ret" ascii
    $s12 = "uck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr" ascii
    $s13 = "(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})" ascii
    $s14 = "eturn \"QTc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s15 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"" ascii
    $s16 = "ction fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s17 = "})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Sx\";})(),(function fuck(" ascii
    $s18 = "MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s19 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s20 = "on fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}