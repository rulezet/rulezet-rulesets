rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_bd4d87f94769_297 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash3       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1  = "return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s2  = "return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s3  = "){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";}" ascii
    $s4  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s5  = "turn \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s6  = "on fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s7  = " fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s8  = "n fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s9  = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s10 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s11 = " fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"C" ascii
    $s12 = "fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LG" ascii
    $s13 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retur" ascii
    $s14 = "unction fuck(){return \"Xg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){retur" ascii
    $s15 = "return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s16 = "(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";" ascii
    $s17 = "ction fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s18 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})()" ascii
    $s19 = "(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii
    $s20 = "Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}