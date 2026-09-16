rule _20160921_74a9afe189b59f0b8148a7f92f42b125_20160921_962ed1e894cd_5404 {
  meta:
    description = "datamaliciousorder - from files 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_962ed1e894cd91f421ad984310ce3140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"

  strings:
    $s1 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return " ascii
    $s2 = "){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})" ascii
    $s3 = "uck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UO" ascii
    $s4 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(" ascii
    $s5 = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}