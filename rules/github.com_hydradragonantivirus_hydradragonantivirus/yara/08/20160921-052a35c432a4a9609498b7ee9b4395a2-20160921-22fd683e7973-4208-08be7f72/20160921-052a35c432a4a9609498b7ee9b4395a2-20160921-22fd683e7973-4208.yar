rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_22fd683e7973_4208 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_a5297a3430b731f07a8b2bd532530907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash3       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash4       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"

  strings:
    $s1 = "){return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})" ascii
    $s2 = " fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"N" ascii
    $s3 = "urn \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s4 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){ret" ascii
    $s5 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}