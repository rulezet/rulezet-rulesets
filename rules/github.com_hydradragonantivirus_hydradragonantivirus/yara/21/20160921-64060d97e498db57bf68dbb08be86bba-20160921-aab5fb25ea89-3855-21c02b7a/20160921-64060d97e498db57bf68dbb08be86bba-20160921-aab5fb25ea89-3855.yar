rule _20160921_64060d97e498db57bf68dbb08be86bba_20160921_aab5fb25ea89_3855 {
  meta:
    description = "datamaliciousorder - from files 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash2       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"

  strings:
    $s1 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s2 = "\"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s3 = "urn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s4 = "return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s5 = "k(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s6 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"To\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}