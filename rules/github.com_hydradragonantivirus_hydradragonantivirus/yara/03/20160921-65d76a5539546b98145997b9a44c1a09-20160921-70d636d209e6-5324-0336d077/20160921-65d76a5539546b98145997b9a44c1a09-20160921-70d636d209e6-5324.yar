rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_70d636d209e6_5324 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_70d636d209e6f109a21746567376cc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"

  strings:
    $s1 = "urn \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s2 = "return \"Py\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3 = "k(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Oh\";}" ascii
    $s4 = " fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"F" ascii
    $s5 = "turn \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}