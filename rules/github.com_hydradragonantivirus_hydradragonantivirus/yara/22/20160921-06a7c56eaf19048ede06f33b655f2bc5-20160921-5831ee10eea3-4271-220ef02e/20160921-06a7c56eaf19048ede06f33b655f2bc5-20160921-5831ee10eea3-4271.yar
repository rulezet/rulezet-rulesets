rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_5831ee10eea3_4271 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_5831ee10eea30ef3b8363cda03eba31a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"

  strings:
    $s1 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retur" ascii
    $s2 = "tion fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){retur" ascii
    $s3 = "ck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt" ascii
    $s4 = "\"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(funct" ascii
    $s5 = "{return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}