rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_1363f95b1c66_2634 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash3       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash4       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash5       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash6       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"
    hash7       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash8       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash9       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "ction fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s2 = ")(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s3 = "ck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s4 = "n fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii
    $s5 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function " ascii
    $s6 = "return \"XFd\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s7 = "rn \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}