rule _20160921_67612c4ac75c1d3511dd9358b66e9fc5_20160921_694d4629e99f_5336 {
  meta:
    description = "datamaliciousorder - from files 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash2       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash3       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash4       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"

  strings:
    $s1 = "fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb" ascii
    $s2 = "){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s3 = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4 = ";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck" ascii
    $s5 = "urn \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}