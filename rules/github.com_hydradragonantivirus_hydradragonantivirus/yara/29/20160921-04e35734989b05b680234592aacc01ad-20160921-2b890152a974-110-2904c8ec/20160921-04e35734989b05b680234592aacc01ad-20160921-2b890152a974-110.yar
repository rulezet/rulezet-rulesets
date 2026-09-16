rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_110 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"

  strings:
    $s1  = " \"MUs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fun" ascii
    $s2  = "uck(){return \"IPu\";})(),(function fuck(){return \"AJs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IP" ascii
    $s3  = "turn \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s4  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s5  = "urn \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s6  = " \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s7  = " fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"I" ascii
    $s8  = "turn \"XFd\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})()," ascii
    $s9  = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s10 = "})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s11 = "uck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb" ascii
    $s12 = "(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(" ascii
    $s13 = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s14 = "),(function fuck(){return \"Oh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s15 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s16 = "on fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s17 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retur" ascii
    $s18 = ";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function f" ascii
    $s19 = "{return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";})()," ascii
    $s20 = "unction fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}