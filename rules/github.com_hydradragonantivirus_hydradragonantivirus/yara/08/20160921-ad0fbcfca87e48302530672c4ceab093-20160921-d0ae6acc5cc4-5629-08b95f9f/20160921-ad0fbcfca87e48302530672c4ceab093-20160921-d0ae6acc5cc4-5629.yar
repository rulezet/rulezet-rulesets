rule _20160921_ad0fbcfca87e48302530672c4ceab093_20160921_d0ae6acc5cc4_5629 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = "n \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s2 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s3 = "{return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})" ascii
    $s4 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"N" ascii
    $s5 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}