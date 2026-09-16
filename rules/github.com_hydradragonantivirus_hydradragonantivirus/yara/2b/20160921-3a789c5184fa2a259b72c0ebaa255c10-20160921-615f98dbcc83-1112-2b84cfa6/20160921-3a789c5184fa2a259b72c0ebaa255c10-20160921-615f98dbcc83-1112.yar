rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_615f98dbcc83_1112 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash3       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash4       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash5       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash6       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1  = "Pu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"VMi\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s2  = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"To\";})" ascii
    $s3  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s4  = "ck(){return \"GJx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s5  = ")(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"To\";})(),(function fuck()" ascii
    $s6  = "{return \"To\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s7  = "urn \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s8  = "uck(){return \"CCb\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu" ascii
    $s9  = "turn \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s10 = "ion fuck(){return \"XHj\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s11 = "{return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})" ascii
    $s12 = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return" ascii
    $s13 = "n \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s14 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"GWo\";})(),(functio" ascii
    $s15 = "\"ZWu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(fun" ascii
    $s16 = "\"Oh\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s17 = "ck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}