rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_511769d99fbe_3396 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash3       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash4       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"

  strings:
    $s1 = " fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"M" ascii
    $s2 = "){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";}" ascii
    $s3 = "(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){re" ascii
    $s4 = "})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s5 = "YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(functio" ascii
    $s6 = "n fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}