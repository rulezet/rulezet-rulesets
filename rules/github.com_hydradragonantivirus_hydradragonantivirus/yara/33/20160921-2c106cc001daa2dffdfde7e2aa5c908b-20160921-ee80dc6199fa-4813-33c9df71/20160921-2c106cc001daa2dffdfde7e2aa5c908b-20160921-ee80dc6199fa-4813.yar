rule _20160921_2c106cc001daa2dffdfde7e2aa5c908b_20160921_ee80dc6199fa_4813 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash2       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "turn \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(" ascii
    $s2 = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s3 = "on fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s4 = "),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s5 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}