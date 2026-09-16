rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_220036ca1d41_3355 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash3       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash4       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash5       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash6       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash7       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"
    hash8       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"
    hash9       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash10      = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1 = ";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f00" ascii
    $s2 = "(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"UEg\";" ascii
    $s3 = " f000(){return \"Iq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TK" ascii
    $s4 = ",(function f000(){return \"MJq\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii
    $s5 = " \"Wy\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(funct" ascii
    $s6 = "turn \"YTp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lo\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}