rule _20160921_5f14ae6f169c53d6d49523d1e13e4ab9_20160921_76495263b6c3_5282 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"
    hash2       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash3       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"

  strings:
    $s1 = "\"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s2 = ";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ug\";})(),(function fuck" ascii
    $s3 = " \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s4 = "uck(){return \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh" ascii
    $s5 = "ck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}