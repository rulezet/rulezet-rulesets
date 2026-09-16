rule _20160921_74a9afe189b59f0b8148a7f92f42b125_20160921_b9d88469e8af_5403 {
  meta:
    description = "datamaliciousorder - from files 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash2       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash3       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"

  strings:
    $s1 = "urn \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s2 = "n \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s3 = "ck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Xg\";" ascii
    $s4 = ")(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s5 = "})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"KVh\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}