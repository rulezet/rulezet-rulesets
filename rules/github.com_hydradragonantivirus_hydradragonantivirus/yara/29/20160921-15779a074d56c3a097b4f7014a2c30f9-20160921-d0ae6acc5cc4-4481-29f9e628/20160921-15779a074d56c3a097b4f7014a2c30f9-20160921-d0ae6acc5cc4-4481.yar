rule _20160921_15779a074d56c3a097b4f7014a2c30f9_20160921_d0ae6acc5cc4_4481 {
  meta:
    description = "datamaliciousorder - from files 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s2 = "eturn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s3 = "){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})" ascii
    $s4 = "{return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";}" ascii
    $s5 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}