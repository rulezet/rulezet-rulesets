rule _20160921_7f682825ca903be9931443996a6639e7_20160921_db727bb0ba7a_3063 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = "IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Py\";})(),(functio" ascii
    $s2 = "n \"Vf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s3 = ",(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){" ascii
    $s4 = "nction fuck(){return \"ZWu\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii
    $s5 = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck" ascii
    $s6 = "(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck()" ascii
    $s7 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}