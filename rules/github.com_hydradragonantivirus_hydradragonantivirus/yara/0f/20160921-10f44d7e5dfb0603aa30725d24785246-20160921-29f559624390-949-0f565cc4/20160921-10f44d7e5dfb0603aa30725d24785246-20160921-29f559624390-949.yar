rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_29f559624390_949 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash3       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"
    hash4       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"
    hash5       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1  = "return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"Cs\";})()," ascii
    $s2  = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(funct" ascii
    $s3  = "){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";}" ascii
    $s4  = "b\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s5  = "{return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})()," ascii
    $s6  = "on fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s7  = "n \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(func" ascii
    $s8  = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s9  = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s10 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function " ascii
    $s11 = "ction fuck(){return \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s12 = "return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})()" ascii
    $s13 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii
    $s14 = "urn \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s15 = " \"We\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(func" ascii
    $s16 = "(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";" ascii
    $s17 = "uck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu" ascii
    $s18 = "nction fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retu" ascii
    $s19 = "(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\";}" ascii
    $s20 = "n fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}