rule _20160921_1664afae318573894e850f85ff412d64_20160921_3b2083afdb57_3417 {
  meta:
    description = "datamaliciousorder - from files 20160921_1664afae318573894e850f85ff412d64.js, 20160921_3b2083afdb57ae7e611f6f42c6787c73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"
    hash2       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"

  strings:
    $s1 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za" ascii
    $s2 = "n \"Mw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3 = "turn \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})()," ascii
    $s4 = "ck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "\"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s6 = "n fuck(){return \"To\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}