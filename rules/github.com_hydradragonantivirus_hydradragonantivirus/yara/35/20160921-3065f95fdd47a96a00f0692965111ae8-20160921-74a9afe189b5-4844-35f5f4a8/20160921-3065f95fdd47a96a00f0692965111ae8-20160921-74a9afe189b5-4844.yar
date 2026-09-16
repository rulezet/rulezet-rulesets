rule _20160921_3065f95fdd47a96a00f0692965111ae8_20160921_74a9afe189b5_4844 {
  meta:
    description = "datamaliciousorder - from files 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash2       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"

  strings:
    $s1 = "rn \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(fun" ascii
    $s2 = "(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck()" ascii
    $s3 = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s4 = "ck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";" ascii
    $s5 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}