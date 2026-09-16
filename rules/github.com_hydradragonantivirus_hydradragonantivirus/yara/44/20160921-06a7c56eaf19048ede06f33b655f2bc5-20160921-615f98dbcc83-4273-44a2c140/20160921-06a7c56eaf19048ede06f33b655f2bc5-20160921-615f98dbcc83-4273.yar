rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_615f98dbcc83_4273 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"

  strings:
    $s1 = "nction fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s3 = "return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s4 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return" ascii
    $s5 = "urn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}