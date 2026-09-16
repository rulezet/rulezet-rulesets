rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_fc08be0621d4_4685 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Ik\";})(),(function fuck" ascii
    $s2 = "uck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s3 = "ck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"PDf" ascii
    $s4 = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s5 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}