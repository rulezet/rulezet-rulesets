rule _20160921_b6d1e9aee3a026c6f266b107f0b88f18_20160921_d0ae6acc5cc4_4033 {
  meta:
    description = "datamaliciousorder - from files 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = " \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s2 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii
    $s3 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"L" ascii
    $s4 = "(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s6 = "Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}