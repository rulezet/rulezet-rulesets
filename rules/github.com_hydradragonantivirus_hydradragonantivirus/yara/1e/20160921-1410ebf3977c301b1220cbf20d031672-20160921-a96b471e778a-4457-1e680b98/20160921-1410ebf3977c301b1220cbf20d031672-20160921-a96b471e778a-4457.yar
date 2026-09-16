rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_a96b471e778a_4457 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s2 = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s3 = "Pu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s4 = "\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s5 = "fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}