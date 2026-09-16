rule _20160921_0f4dee7115fed314f330d52696c0d1d1_20160921_11906f10ee01_4371 {
  meta:
    description = "datamaliciousorder - from files 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash2       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash3       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash4       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash5       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash6       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash7       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash8       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash9       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash10      = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash11      = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash12      = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"
    hash13      = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash14      = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash15      = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash16      = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash17      = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash18      = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash19      = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"
    hash20      = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"
    hash21      = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"
    hash22      = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"
    hash23      = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash24      = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"
    hash25      = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})()" ascii
    $s2 = "function fuck(){return \"Yk\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){ret" ascii
    $s3 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Mw\";})(),(function " ascii
    $s4 = "{return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZWu\";})(" ascii
    $s5 = ")(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}