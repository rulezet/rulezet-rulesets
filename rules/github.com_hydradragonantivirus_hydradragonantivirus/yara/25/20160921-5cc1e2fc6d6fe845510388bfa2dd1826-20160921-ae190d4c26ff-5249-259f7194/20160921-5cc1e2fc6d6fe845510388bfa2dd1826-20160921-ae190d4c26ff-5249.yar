rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_ae190d4c26ff_5249 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"

  strings:
    $s1 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"V" ascii
    $s2 = "rn \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3 = "tion fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s4 = "{return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})" ascii
    $s5 = "(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}