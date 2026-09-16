rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_b9d88469e8af_5238 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash3       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"

  strings:
    $s1 = "ck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu" ascii
    $s2 = "k(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm" ascii
    $s3 = ";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"YQt\";})(),(function f" ascii
    $s4 = "ion fuck(){return \"GNm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s5 = "return \"Np\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}