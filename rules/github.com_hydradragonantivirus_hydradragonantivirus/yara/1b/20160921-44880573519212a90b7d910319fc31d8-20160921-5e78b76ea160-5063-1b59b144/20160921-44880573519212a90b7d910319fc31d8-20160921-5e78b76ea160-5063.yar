rule _20160921_44880573519212a90b7d910319fc31d8_20160921_5e78b76ea160_5063 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash3       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash4       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"I" ascii
    $s2 = "\"Ve\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(funct" ascii
    $s3 = "){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";}" ascii
    $s4 = "n \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fu" ascii
    $s5 = "eturn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}