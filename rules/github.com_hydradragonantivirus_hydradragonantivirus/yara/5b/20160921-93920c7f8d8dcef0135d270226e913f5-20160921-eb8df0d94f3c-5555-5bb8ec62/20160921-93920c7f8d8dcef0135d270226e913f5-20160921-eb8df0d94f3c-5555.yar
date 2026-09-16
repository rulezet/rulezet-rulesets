rule _20160921_93920c7f8d8dcef0135d270226e913f5_20160921_eb8df0d94f3c_5555 {
  meta:
    description = "datamaliciousorder - from files 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash2       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "ck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s3 = "){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Za\";}" ascii
    $s4 = "ction fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s5 = "g\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}