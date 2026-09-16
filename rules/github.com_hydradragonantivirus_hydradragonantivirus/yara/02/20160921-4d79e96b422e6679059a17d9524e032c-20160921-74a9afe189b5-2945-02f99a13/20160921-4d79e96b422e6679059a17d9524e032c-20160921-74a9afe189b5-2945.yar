rule _20160921_4d79e96b422e6679059a17d9524e032c_20160921_74a9afe189b5_2945 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash2       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"

  strings:
    $s1 = "n \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s2 = "fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MU" ascii
    $s3 = "ck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\"" ascii
    $s4 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return" ascii
    $s5 = ")(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck()" ascii
    $s6 = "return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s7 = "n \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}