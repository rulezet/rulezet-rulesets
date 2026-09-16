rule _20160921_a96b471e778a8101c168e06727d930fb_20160921_f575ae0885e7_5614 {
  meta:
    description = "datamaliciousorder - from files 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_f575ae0885e764a3ea3a621283d492e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash2       = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"

  strings:
    $s1 = ")(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s2 = "(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck" ascii
    $s3 = "turn \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4 = "\"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s5 = "nction fuck(){return \"Jg\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}