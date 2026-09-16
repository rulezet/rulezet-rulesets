rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_b5efb4ba3e71_2747 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"

  strings:
    $s1 = "nction fuck(){return \"Nm\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s2 = "})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s3 = "function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){ret" ascii
    $s4 = "TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(functio" ascii
    $s5 = "return \"Jh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Et\";})()," ascii
    $s6 = "ction fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s7 = "){return \"Et\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}