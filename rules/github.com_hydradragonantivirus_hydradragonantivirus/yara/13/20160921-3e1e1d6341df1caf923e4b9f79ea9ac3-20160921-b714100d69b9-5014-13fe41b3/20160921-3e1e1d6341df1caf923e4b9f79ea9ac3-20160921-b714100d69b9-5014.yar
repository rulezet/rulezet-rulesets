rule _20160921_3e1e1d6341df1caf923e4b9f79ea9ac3_20160921_b714100d69b9_5014 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash3       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash4       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"

  strings:
    $s1 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s2 = "function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s3 = " \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(fu" ascii
    $s4 = " fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s5 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}