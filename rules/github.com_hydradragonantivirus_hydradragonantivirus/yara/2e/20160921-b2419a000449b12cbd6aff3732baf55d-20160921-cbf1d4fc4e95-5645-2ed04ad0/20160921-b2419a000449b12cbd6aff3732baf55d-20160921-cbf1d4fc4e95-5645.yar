rule _20160921_b2419a000449b12cbd6aff3732baf55d_20160921_cbf1d4fc4e95_5645 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash2       = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"

  strings:
    $s1 = "turn \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s2 = "){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";}" ascii
    $s3 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){ret" ascii
    $s4 = "ck(){return \"Ot\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";" ascii
    $s5 = "h\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}