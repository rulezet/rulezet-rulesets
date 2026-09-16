rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_105b4651b716_3188 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash3       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash4       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash5       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash6       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash7       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash8       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash9       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash10      = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash11      = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash12      = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1 = " \"To\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(functi" ascii
    $s2 = "on fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return " ascii
    $s3 = "ion fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"" ascii
    $s4 = "){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Ar\";})(" ascii
    $s5 = ";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuc" ascii
    $s6 = "),(function fuck(){return \"Sx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}