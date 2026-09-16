rule _20160921_bd4d87f94769a02253ed6ac2e747557f_20160921_dcd6ef8585af_4043 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash2       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"
    hash3       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "x\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function " ascii
    $s2 = "ion fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s3 = "ion fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s5 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){retu" ascii
    $s6 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}