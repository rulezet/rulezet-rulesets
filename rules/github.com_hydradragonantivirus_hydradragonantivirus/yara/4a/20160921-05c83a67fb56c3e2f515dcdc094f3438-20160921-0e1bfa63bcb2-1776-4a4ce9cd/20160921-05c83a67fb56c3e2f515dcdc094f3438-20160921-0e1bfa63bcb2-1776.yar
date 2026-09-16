rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_0e1bfa63bcb2_1776 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_78345276f684d53628bbcac810994182.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash3       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash4       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash5       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash6       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash7       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash8       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash9       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash10      = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash11      = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash12      = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash13      = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash14      = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash15      = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"
    hash16      = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"
    hash17      = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash18      = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"
    hash19      = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"
    hash20      = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1  = "turn \"XCr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s2  = "(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){" ascii
    $s3  = "})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuc" ascii
    $s4  = "ck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";}" ascii
    $s5  = " \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(fun" ascii
    $s6  = " fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo" ascii
    $s7  = "\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fu" ascii
    $s8  = "turn \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(fu" ascii
    $s9  = "uck(){return \"To\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";" ascii
    $s10 = "nction fuck(){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}