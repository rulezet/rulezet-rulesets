rule _20160921_67db5ecea174c85a1df44685d8781acd_20160921_a6679b5a153c_1597 {
  meta:
    description = "datamaliciousorder - from files 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash2       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash3       = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"

  strings:
    $s1  = "ction fuck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s2  = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s3  = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii
    $s4  = "uck(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\"" ascii
    $s5  = "function fuck(){return \"Py\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s6  = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai\";}" ascii
    $s7  = "fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Py" ascii
    $s8  = "unction fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){ret" ascii
    $s9  = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})()" ascii
    $s10 = " \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(func" ascii
    $s11 = "(){return \"Ai\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";}" ascii
    $s12 = "rn \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}