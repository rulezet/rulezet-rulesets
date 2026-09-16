rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_6d7b654a484a_504 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash3       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash4       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash5       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash6       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash7       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash8       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1  = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return" ascii
    $s2  = "})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(function fuc" ascii
    $s3  = "n \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s4  = " fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"ADy" ascii
    $s5  = "function fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s6  = "urn \"Mw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s7  = "on fuck(){return \"Py\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s8  = "n fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii
    $s9  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"XCr" ascii
    $s10 = "){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"PDf\";" ascii
    $s11 = "u\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Wo0\";})(),(function " ascii
    $s12 = "})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuc" ascii
    $s13 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ai\";})(),(functi" ascii
    $s14 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(f" ascii
    $s15 = "n fuck(){return \"XCr\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s16 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s17 = " fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii
    $s18 = " \"Xw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Dc\";})(),(functi" ascii
    $s19 = "on fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"X" ascii
    $s20 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}