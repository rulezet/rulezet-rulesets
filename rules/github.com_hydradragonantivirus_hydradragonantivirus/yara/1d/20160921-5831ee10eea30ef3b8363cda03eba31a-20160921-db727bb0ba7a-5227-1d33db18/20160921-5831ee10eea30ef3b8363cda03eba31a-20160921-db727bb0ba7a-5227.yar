rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_db727bb0ba7a_5227 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(f" ascii
    $s2 = "eturn \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})()," ascii
    $s3 = "),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(" ascii
    $s4 = "fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"O" ascii
    $s5 = "\"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}