rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_85f2776f4fe6_1889 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash3       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"
    hash4       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1  = "urn \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s2  = "nction fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s3  = "eturn \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})()" ascii
    $s4  = "(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";}" ascii
    $s5  = "),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s6  = "ck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";" ascii
    $s7  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Y" ascii
    $s8  = "n \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s9  = "{return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})" ascii
    $s10 = "\"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}