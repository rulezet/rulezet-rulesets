rule _20160921_d29f34806a7d94f2bbb7a733fc4c43bc_20160921_df51150cb497_5701 {
  meta:
    description = "datamaliciousorder - from files 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash2       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(" ascii
    $s2 = "return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})()" ascii
    $s3 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){" ascii
    $s4 = " \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(fu" ascii
    $s5 = "uck(){return \"XFd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}