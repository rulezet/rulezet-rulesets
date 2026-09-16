rule _20160921_469953d9833167e141d9f086f1f41437_20160921_ae190d4c26ff_5069 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"

  strings:
    $s1 = " \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s2 = "{return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";}" ascii
    $s3 = "rn \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(" ascii
    $s4 = " fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s5 = "nction fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}