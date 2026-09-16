rule _20160921_bd4d87f94769a02253ed6ac2e747557f_20160921_dcd6ef8585af_79 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash2       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1  = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Wo0\";" ascii
    $s2  = "ion fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return" ascii
    $s3  = "fuck(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu" ascii
    $s4  = "LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s5  = "{return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s6  = "(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(" ascii
    $s7  = "ck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"AUx" ascii
    $s8  = " \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s9  = "return \"ZLd\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s10 = "eturn \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})()," ascii
    $s11 = "rn \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(f" ascii
    $s12 = "turn \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s13 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s14 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retur" ascii
    $s15 = "u\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s16 = "ion fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s17 = "uck(){return \"XHj\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s18 = "ction fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s19 = "k(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy" ascii
    $s20 = "k(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}