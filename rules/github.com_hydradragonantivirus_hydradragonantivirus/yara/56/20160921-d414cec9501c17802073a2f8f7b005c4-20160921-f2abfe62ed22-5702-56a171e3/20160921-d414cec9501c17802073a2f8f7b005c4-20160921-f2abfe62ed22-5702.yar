rule _20160921_d414cec9501c17802073a2f8f7b005c4_20160921_f2abfe62ed22_5702 {
  meta:
    description = "datamaliciousorder - from files 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash2       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){r" ascii
    $s2 = "ck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s3 = "{return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(" ascii
    $s4 = "return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZVi\";})()" ascii
    $s5 = "{return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}