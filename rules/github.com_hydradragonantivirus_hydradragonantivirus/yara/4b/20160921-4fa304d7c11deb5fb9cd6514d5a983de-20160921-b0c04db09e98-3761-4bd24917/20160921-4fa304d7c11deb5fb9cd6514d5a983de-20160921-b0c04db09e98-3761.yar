rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_b0c04db09e98_3761 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"

  strings:
    $s1 = "\"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(funct" ascii
    $s2 = "nction fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return" ascii
    $s3 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"" ascii
    $s4 = "),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){r" ascii
    $s5 = "})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck" ascii
    $s6 = "urn \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}