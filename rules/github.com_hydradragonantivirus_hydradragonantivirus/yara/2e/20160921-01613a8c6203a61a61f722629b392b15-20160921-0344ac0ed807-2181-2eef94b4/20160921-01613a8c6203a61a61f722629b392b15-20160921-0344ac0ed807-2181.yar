rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_0344ac0ed807_2181 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_099ae50c92fa9b72abe88204de915580.js, 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_76157564ae9f7ad7ec97100684b2a5ce.js, 20160921_8753c13c904d4c1e9e4a848591336ee8.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js, 20160921_df47c7f57f308287ca344dcc34150b37.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash3       = "344e6822e369c3beb064ffee655d0ce0db901d1bada577cd8f338fc2aec06cb8"
    hash4       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash5       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash6       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash7       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash8       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash9       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash10      = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash11      = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash12      = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash13      = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash14      = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"
    hash15      = "57611d1ad2ff9881d73dbaf53bfa8657402affd956dea32b9fc2afae375ffb9f"
    hash16      = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash17      = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash18      = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"
    hash19      = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash20      = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"
    hash21      = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"
    hash22      = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"
    hash23      = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"
    hash24      = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"
    hash25      = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = "f\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xg\";})(),(function " ascii
    $s2 = "return \"Na\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s3 = "\"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"To\";})(),(functio" ascii
    $s4 = "),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){" ascii
    $s5 = "on fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"" ascii
    $s6 = "ction fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retu" ascii
    $s7 = "(){return \"Wn\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";}" ascii
    $s8 = "{return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}