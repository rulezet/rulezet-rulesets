rule _20160921_4cda342a49d7c489fce63509619cc08e_20160921_88a4a74b87ab_97 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash2       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"

  strings:
    $s1  = "n \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s2  = "\"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii
    $s3  = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(" ascii
    $s4  = " fuck(){return \"DRx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"" ascii
    $s5  = "function fuck(){return \"Cd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s6  = " fuck(){return \"Xw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii
    $s7  = "urn \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(fu" ascii
    $s8  = "tion fuck(){return \"XCr\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retur" ascii
    $s9  = "\"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(func" ascii
    $s10 = "uck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\"" ascii
    $s11 = "eturn \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s12 = "){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s13 = "eturn \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})()," ascii
    $s14 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"" ascii
    $s15 = "return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s16 = "){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"UXf\";}" ascii
    $s17 = "nction fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){retu" ascii
    $s18 = "n fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s19 = "turn \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s20 = "turn \"ZVi\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}