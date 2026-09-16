rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_73310531aa4a_3873 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash3       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"

  strings:
    $s1 = "nction fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s2 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s3 = "u\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s4 = "tion fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){retur" ascii
    $s5 = "return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s6 = "{return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}