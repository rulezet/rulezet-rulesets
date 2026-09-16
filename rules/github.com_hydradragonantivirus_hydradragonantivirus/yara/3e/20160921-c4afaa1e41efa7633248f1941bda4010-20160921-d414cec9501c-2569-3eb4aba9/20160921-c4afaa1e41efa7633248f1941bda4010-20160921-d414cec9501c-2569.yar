rule _20160921_c4afaa1e41efa7633248f1941bda4010_20160921_d414cec9501c_2569 {
  meta:
    description = "datamaliciousorder - from files 20160921_c4afaa1e41efa7633248f1941bda4010.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = "MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s2 = "Qr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(function" ascii
    $s3 = "){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})" ascii
    $s4 = "\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo\";})(),(function f" ascii
    $s5 = "uck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IO" ascii
    $s6 = "u\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function " ascii
    $s7 = " \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s8 = "){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}