rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_78345276f684_4237 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_78345276f684d53628bbcac810994182.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash3       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1 = "fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu" ascii
    $s2 = "s\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function " ascii
    $s3 = "s\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s4 = "n fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}