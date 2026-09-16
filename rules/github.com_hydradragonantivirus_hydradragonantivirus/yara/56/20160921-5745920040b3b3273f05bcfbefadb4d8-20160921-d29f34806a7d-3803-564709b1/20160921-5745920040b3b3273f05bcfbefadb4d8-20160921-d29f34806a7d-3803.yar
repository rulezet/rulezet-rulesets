rule _20160921_5745920040b3b3273f05bcfbefadb4d8_20160921_d29f34806a7d_3803 {
  meta:
    description = "datamaliciousorder - from files 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "turn \"Xw\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s2 = "k(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";" ascii
    $s3 = "return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ve\";})()," ascii
    $s4 = "ion fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s5 = "{return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()" ascii
    $s6 = "urn \"Ot\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}