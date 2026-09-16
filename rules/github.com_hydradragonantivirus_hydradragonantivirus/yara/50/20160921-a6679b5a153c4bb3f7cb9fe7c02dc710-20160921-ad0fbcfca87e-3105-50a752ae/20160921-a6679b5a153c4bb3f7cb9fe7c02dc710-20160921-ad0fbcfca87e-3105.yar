rule _20160921_a6679b5a153c4bb3f7cb9fe7c02dc710_20160921_ad0fbcfca87e_3105 {
  meta:
    description = "datamaliciousorder - from files 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash2       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"

  strings:
    $s1 = "\"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(func" ascii
    $s2 = "uck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf" ascii
    $s3 = "ction fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\"" ascii
    $s5 = "return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s6 = "on fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s7 = "(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}