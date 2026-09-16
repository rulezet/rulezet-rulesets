rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_18eedffe02de_503 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash3       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash4       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash5       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash6       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash7       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash8       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash9       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash10      = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash11      = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash12      = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash13      = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"
    hash14      = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"
    hash15      = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash16      = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1  = ",(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){r" ascii
    $s2  = "unction fuck(){return \"GWo\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s3  = "turn \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Ar\";})(),(f" ascii
    $s4  = "\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ar\";})(),(function f" ascii
    $s5  = "unction fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retur" ascii
    $s6  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"G" ascii
    $s7  = "eturn \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(" ascii
    $s8  = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return " ascii
    $s9  = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s10 = "turn \"XHj\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s11 = "(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck()" ascii
    $s12 = "urn \"Pc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s13 = "){return \"CCb\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZLd\";}" ascii
    $s14 = ";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"RAi\";})(),(function fuc" ascii
    $s15 = ")(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s16 = "rn \"Vf\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s17 = "n fuck(){return \"GJx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s18 = "function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retu" ascii
    $s19 = "k(){return \"Xg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s20 = "(function fuck(){return \"Hs\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}