rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_3a10cf806284_2777 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_5143fd2835d058f3854ef7b166166de4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash3       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"

  strings:
    $s1 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii
    $s2 = "tion fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return " ascii
    $s3 = ")(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuc" ascii
    $s4 = "eturn \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s5 = "eturn \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s6 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(function " ascii
    $s7 = " \"GWo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}