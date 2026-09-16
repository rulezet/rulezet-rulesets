rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_0ae28061d65a_135 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_d88b1be24c583b3513de141e173a825f.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js, 20160921_dd42e850834f3af27a08edf609a699b5.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash3       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash4       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash5       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash6       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash7       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash8       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash9       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash10      = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash11      = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash12      = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"
    hash13      = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"
    hash14      = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"
    hash15      = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"
    hash16      = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"
    hash17      = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"
    hash18      = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1  = "ion fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s2  = "Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IOs\";})(),(function" ascii
    $s3  = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Xw\";}" ascii
    $s4  = "turn \"Ot\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(f" ascii
    $s5  = "ion fuck(){return \"Et\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Sx\";})(),(function fuck()" ascii
    $s7  = "function fuck(){return \"Wo0\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s8  = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Qh\";})(),(functio" ascii
    $s9  = "tion fuck(){return \"Ve\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s10 = "eturn \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s11 = "on fuck(){return \"We\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"" ascii
    $s12 = "ck(){return \"Ar\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s13 = "\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function f" ascii
    $s14 = "),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){" ascii
    $s15 = "Cr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s16 = "urn \"We\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s17 = " fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s18 = "(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){r" ascii
    $s19 = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return" ascii
    $s20 = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}