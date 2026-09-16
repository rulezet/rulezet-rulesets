rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_78345276f684_1988 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_78345276f684d53628bbcac810994182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"

  strings:
    $s1 = "c\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function" ascii
    $s2 = "{return \"Xw\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})()," ascii
    $s3 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){ret" ascii
    $s4 = "function fuck(){return \"Et\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){re" ascii
    $s5 = "turn \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s6 = "function fuck(){return \"Tv\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retu" ascii
    $s7 = "ck(){return \"Jh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Et\";" ascii
    $s8 = ")(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function fuck(" ascii
    $s9 = "ck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}