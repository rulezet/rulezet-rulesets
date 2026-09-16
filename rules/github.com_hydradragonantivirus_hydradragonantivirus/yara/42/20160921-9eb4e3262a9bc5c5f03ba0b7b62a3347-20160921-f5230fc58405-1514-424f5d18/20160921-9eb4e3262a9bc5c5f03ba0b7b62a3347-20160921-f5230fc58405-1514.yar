rule _20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347_20160921_f5230fc58405_1514 {
  meta:
    description = "datamaliciousorder - from files 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash2       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1  = "\"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(funct" ascii
    $s2  = "s\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii
    $s3  = "on fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s4  = "{return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})" ascii
    $s5  = "{return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Xw\";})(" ascii
    $s6  = "nction fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s7  = ",(function fuck(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){" ascii
    $s8  = "unction fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s9  = "nction fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s10 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"" ascii
    $s11 = "(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";" ascii
    $s12 = ";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s13 = "ion fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}