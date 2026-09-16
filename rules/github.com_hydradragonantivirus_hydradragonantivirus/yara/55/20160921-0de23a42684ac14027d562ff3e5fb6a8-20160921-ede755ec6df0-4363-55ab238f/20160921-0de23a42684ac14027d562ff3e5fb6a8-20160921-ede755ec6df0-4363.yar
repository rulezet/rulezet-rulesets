rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_ede755ec6df0_4363 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"V" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s3 = "ck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr" ascii
    $s4 = "){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";}" ascii
    $s5 = "IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}