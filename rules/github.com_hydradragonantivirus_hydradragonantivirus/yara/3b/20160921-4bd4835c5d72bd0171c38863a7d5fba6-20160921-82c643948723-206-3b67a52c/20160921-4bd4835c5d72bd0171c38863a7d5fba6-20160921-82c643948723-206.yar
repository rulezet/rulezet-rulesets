rule _20160921_4bd4835c5d72bd0171c38863a7d5fba6_20160921_82c643948723_206 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash2       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash3       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"

  strings:
    $s1  = " \"MIl\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s2  = " fuck(){return \"Zy\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DR" ascii
    $s3  = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck" ascii
    $s4  = "uck(){return \"AUx\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s5  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return " ascii
    $s6  = "unction fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){ret" ascii
    $s7  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"" ascii
    $s8  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){retur" ascii
    $s9  = "unction fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s10 = "})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"AUx\";})(),(function fuc" ascii
    $s11 = "\"Et\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s12 = "ction fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retur" ascii
    $s13 = "uck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s14 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"UXf\";})(),(function fuc" ascii
    $s15 = "(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})" ascii
    $s16 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s17 = "rn \"Yk\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s18 = "eturn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"QTc\";})()" ascii
    $s19 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){ret" ascii
    $s20 = "k(){return \"XFd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Np\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}