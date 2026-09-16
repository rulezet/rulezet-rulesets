rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_0e1bfa63bcb2_4153 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash3       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash4       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash5       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash6       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"
    hash7       = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"
    hash8       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"
    hash9       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuc" ascii
    $s2 = "n \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(func" ascii
    $s3 = "k(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";}" ascii
    $s4 = ",(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck()" ascii
    $s5 = "fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KV" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}