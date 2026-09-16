rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_42353ce25753_380 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js, 20160921_e53844f4bb18305322896332fbd017e8.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash3       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash4       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"
    hash5       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash6       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash7       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash8       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"
    hash9       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"
    hash10      = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1  = "ck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ug\";" ascii
    $s2  = "(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ar\";})(),(function fuck()" ascii
    $s3  = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Za\";})(),(function fuck" ascii
    $s4  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){" ascii
    $s5  = "),(function fuck(){return \"Zy\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){" ascii
    $s6  = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retur" ascii
    $s7  = "n fuck(){return \"Cd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IP" ascii
    $s8  = "fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"RAi" ascii
    $s9  = "rn \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s10 = "return \"XHj\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s11 = "urn \"Dc\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s12 = ")(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(" ascii
    $s13 = "Pu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function " ascii
    $s14 = "nction fuck(){return \"To\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s15 = "nction fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){retur" ascii
    $s16 = " \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(funct" ascii
    $s17 = "rn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(fun" ascii
    $s18 = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s19 = "return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Wo0\";})(" ascii
    $s20 = "function fuck(){return \"Pc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}