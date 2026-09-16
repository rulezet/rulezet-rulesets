rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_06a2269d96cb_4212 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash3       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash4       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash5       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash6       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash7       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash8       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash9       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash10      = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash11      = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash12      = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"
    hash13      = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = "unction fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){ret" ascii
    $s2 = "ck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\"" ascii
    $s3 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s4 = "n \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s5 = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Dc\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}