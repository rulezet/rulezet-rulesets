rule _20160921_9dc96613aa4c64f92e4ff218607f50d0_20160921_a96b471e778a_5590 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dc96613aa4c64f92e4ff218607f50d0.js, 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash3       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){retur" ascii
    $s2 = "ck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\"" ascii
    $s3 = "unction fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s4 = "ction fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii
    $s5 = "{return \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}