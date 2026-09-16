rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_24cca85b9483_3426 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js, 20160922_37d3775ea966a92be28550dbc5135955.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash4       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash5       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash6       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash7       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash8       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash9       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"
    hash10      = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"
    hash11      = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "ion f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"MJq\";})(),(function f000(){return" ascii
    $s2 = "(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Mc\";})(),(function f000(){re" ascii
    $s3 = "turn \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(f" ascii
    $s4 = "Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Nv\";})(),(functio" ascii
    $s5 = "})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MBb\";})(),(function f00" ascii
    $s6 = "){return \"TKp\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Tn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}