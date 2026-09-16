rule _20160921_78345276f684d53628bbcac810994182_20160921_d97203a3a0e9_5412 {
  meta:
    description = "datamaliciousorder - from files 20160921_78345276f684d53628bbcac810994182.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash2       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"
    hash3       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "ck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\"" ascii
    $s2 = "{return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3 = ",(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s4 = "rn \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(f" ascii
    $s5 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}