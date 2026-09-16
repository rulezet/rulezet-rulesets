rule _20160921_063094039ef79437a260d3dde960797a_20160921_67db5ecea174_2649 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash3       = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"

  strings:
    $s1 = "n \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s2 = "on fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"" ascii
    $s3 = ";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function f" ascii
    $s4 = "\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"KVh\";})(),(function" ascii
    $s5 = "return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s6 = "(){return \"QTc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s7 = "{return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}