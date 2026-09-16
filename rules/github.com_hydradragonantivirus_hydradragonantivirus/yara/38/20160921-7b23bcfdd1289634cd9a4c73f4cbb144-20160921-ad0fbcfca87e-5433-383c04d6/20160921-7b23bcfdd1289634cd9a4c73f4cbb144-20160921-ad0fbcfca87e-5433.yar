rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_ad0fbcfca87e_5433 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"

  strings:
    $s1 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"" ascii
    $s2 = "){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";}" ascii
    $s3 = "\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function " ascii
    $s4 = "uck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "eturn \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}