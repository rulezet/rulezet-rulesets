rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_11906f10ee01_3239 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_c694815b18c140f34c0f79f86106d901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash3       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash4       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash5       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash6       = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"

  strings:
    $s1 = ",(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){" ascii
    $s2 = "k(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";" ascii
    $s3 = " \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(func" ascii
    $s4 = ";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck" ascii
    $s5 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return" ascii
    $s6 = "urn \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}