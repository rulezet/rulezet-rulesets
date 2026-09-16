rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_1410ebf3977c_741 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash3       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash4       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash5       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash6       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash7       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash8       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash9       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash10      = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash11      = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash12      = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash13      = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash14      = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash15      = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"
    hash16      = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"
    hash17      = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"
    hash18      = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash19      = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1  = "turn \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})()," ascii
    $s2  = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Qh\";})(),(fu" ascii
    $s3  = "urn \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s4  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"GN" ascii
    $s5  = "uck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"UXf" ascii
    $s6  = "eturn \"Mw\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s7  = "(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(" ascii
    $s8  = "\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Np\";})(),(function fu" ascii
    $s9  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Av" ascii
    $s10 = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})()," ascii
    $s11 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){" ascii
    $s12 = "nction fuck(){return \"Yk\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retu" ascii
    $s13 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(func" ascii
    $s14 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"UXf\";})(),(function f" ascii
    $s15 = "unction fuck(){return \"Xw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retu" ascii
    $s16 = "\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function " ascii
    $s17 = "nction fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return" ascii
    $s18 = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ZVi\";" ascii
    $s19 = "urn \"Vf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s20 = "unction fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}