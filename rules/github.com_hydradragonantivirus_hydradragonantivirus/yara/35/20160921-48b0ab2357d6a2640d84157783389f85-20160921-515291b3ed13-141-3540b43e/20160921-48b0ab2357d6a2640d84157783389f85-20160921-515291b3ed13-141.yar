rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_515291b3ed13_141 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"

  strings:
    $s1  = "ction fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii
    $s2  = "),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(" ascii
    $s3  = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s4  = "(){return \"Wo\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s5  = "n fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"I" ascii
    $s6  = "ction fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s7  = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"QTc\";})(),(function fuck" ascii
    $s8  = "fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq" ascii
    $s9  = "uck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Py" ascii
    $s10 = "fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IP" ascii
    $s11 = "urn \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s12 = "fuck(){return \"XFd\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"X" ascii
    $s13 = "fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"MUs" ascii
    $s14 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s15 = "unction fuck(){return \"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s16 = "return \"Xw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})()," ascii
    $s17 = "eturn \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s18 = "n \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s19 = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s20 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}