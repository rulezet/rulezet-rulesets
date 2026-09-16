rule _20160921_063094039ef79437a260d3dde960797a_20160921_0de23a42684a_502 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_70d636d209e6f109a21746567376cc81.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_9b80c329004df146d978cb7b31b22c05.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_c694815b18c140f34c0f79f86106d901.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash3       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash4       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash5       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash6       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash7       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash8       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash9       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash10      = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"
    hash11      = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash12      = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"
    hash13      = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash14      = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"
    hash15      = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"
    hash16      = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"
    hash17      = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"PDf\";})(),(function fu" ascii
    $s2  = "(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ai\";" ascii
    $s3  = "Pu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function" ascii
    $s4  = "),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii
    $s5  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s6  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"" ascii
    $s7  = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return" ascii
    $s8  = "Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s9  = ",(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){re" ascii
    $s10 = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Mw\";})(),(function fuc" ascii
    $s11 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s12 = "Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s13 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return" ascii
    $s14 = "k(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";" ascii
    $s15 = "IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Mw\";})(),(functio" ascii
    $s16 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s17 = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return" ascii
    $s18 = "ck(){return \"Nm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\"" ascii
    $s19 = "turn \"XHj\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s20 = "rn \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}