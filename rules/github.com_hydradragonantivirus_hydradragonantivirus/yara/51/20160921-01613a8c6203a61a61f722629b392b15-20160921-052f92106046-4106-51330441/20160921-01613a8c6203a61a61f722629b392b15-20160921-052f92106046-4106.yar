rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_052f92106046_4106 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_70d636d209e6f109a21746567376cc81.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js, 20160921_dc67677da64e0c03fb55538663264839.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash3       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash4       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"
    hash5       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash6       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash7       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash8       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"
    hash9       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"
    hash10      = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "n fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"" ascii
    $s2 = "uck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\"" ascii
    $s3 = "urn \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(fu" ascii
    $s4 = "\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function " ascii
    $s5 = "(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}