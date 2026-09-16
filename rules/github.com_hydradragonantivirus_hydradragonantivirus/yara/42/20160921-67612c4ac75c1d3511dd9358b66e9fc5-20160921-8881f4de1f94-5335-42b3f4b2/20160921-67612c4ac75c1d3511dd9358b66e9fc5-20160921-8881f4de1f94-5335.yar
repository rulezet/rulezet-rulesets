rule _20160921_67612c4ac75c1d3511dd9358b66e9fc5_20160921_8881f4de1f94_5335 {
  meta:
    description = "datamaliciousorder - from files 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash2       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fu" ascii
    $s2 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return " ascii
    $s3 = "turn \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})()," ascii
    $s4 = "n fuck(){return \"ZLd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s5 = "n fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}