rule _20160921_885a9e110f52f3ca103e4718673adb3b_20160921_9ab244a7866d_77 {
  meta:
    description = "datamaliciousorder - from files 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash2       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"

  strings:
    $s1  = "Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function" ascii
    $s2  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return" ascii
    $s3  = "eturn \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})()" ascii
    $s4  = "Pu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s5  = "unction fuck(){return \"XFd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){re" ascii
    $s6  = "eturn \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s7  = "\"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s8  = "eturn \"Sx\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})()" ascii
    $s9  = "unction fuck(){return \"ZLd\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s10 = "turn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s11 = ")(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(" ascii
    $s12 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s13 = "uck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Dc" ascii
    $s14 = "ck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx" ascii
    $s15 = "return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s16 = "PDf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(funct" ascii
    $s17 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){retu" ascii
    $s18 = "rn \"Zy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s19 = "Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s20 = "Ts\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"ADy\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}