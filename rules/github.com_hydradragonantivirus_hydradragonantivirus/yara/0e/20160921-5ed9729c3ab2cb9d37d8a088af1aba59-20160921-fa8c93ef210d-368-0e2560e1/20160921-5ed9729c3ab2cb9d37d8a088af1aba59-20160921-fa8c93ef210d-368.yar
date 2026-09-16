rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_fa8c93ef210d_368 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1  = "n \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xg\";})(),(funct" ascii
    $s2  = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"YAv\";})(),(functi" ascii
    $s3  = "tion fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s4  = " \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Ik\";})(),(functi" ascii
    $s5  = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retu" ascii
    $s6  = "return \"DRx\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})()" ascii
    $s7  = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Yk\";})(),(f" ascii
    $s8  = "n \"Xw\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"GWo\";})(),(fun" ascii
    $s9  = "\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Ai\";})(),(function " ascii
    $s10 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii
    $s11 = "eturn \"Nm\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s12 = "f\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s13 = "){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jg\";})" ascii
    $s14 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Jh\";})(),(funct" ascii
    $s15 = "(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){" ascii
    $s16 = "ck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd" ascii
    $s17 = "turn \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s18 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s19 = "n fuck(){return \"YQt\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"A" ascii
    $s20 = "DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Wo0\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}