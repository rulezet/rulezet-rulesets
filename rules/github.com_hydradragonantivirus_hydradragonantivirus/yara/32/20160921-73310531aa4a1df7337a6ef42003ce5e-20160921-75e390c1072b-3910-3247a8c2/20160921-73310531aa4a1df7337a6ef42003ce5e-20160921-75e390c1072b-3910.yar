rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_75e390c1072b_3910 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash3       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash4       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash5       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "urn \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})(),(f" ascii
    $s2 = "on fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"" ascii
    $s3 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return" ascii
    $s4 = "(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){re" ascii
    $s5 = "uck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Jh\"" ascii
    $s6 = "turn \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}