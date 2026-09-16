rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_97811319fb50_5401 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash3       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = "fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"I" ascii
    $s2 = "),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s3 = "){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";}" ascii
    $s4 = "})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck" ascii
    $s5 = "ck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}