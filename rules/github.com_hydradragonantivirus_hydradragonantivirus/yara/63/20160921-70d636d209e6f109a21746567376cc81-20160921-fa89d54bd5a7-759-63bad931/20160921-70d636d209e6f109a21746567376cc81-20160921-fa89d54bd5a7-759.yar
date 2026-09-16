rule _20160921_70d636d209e6f109a21746567376cc81_20160921_fa89d54bd5a7_759 {
  meta:
    description = "datamaliciousorder - from files 20160921_70d636d209e6f109a21746567376cc81.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1  = "){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})" ascii
    $s2  = "turn \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"YQt\";})()," ascii
    $s3  = "tion fuck(){return \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s4  = "ion fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s5  = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return " ascii
    $s6  = "n fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii
    $s7  = "fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb" ascii
    $s8  = " fuck(){return \"Yk\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Y" ascii
    $s9  = "\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fu" ascii
    $s10 = "n \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s11 = "function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s12 = " fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s13 = "urn \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s14 = "k(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr" ascii
    $s15 = "(),(function fuck(){return \"To\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){" ascii
    $s16 = "XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s17 = "rn \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s18 = "rn \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MIl\";})(),(" ascii
    $s19 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck" ascii
    $s20 = ")(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}