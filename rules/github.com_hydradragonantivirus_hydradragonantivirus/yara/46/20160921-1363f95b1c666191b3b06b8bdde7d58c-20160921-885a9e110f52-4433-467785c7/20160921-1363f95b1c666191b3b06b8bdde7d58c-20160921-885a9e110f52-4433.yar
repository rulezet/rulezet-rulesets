rule _20160921_1363f95b1c666191b3b06b8bdde7d58c_20160921_885a9e110f52_4433 {
  meta:
    description = "datamaliciousorder - from files 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash2       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash3       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash4       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1 = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fu" ascii
    $s2 = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(" ascii
    $s3 = "n fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"" ascii
    $s4 = "eturn \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})()," ascii
    $s5 = " fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}