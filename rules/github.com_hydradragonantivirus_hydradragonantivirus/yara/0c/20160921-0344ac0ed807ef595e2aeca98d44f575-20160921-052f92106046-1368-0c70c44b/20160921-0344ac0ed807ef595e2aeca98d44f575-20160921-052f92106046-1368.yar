rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_052f92106046_1368 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_dc67677da64e0c03fb55538663264839.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash3       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash4       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash5       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash6       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash7       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash8       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash9       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash10      = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash11      = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash12      = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash13      = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash14      = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash15      = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"
    hash16      = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"
    hash17      = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1  = "\"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s2  = "turn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})(),(" ascii
    $s3  = "function fuck(){return \"Ar\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){ret" ascii
    $s4  = "\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function " ascii
    $s5  = "nction fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return" ascii
    $s6  = "})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s7  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s8  = "To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s9  = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return" ascii
    $s10 = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s11 = "){return \"QTc\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(" ascii
    $s12 = "urn \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Fv\";})(),(f" ascii
    $s13 = "n fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv" ascii
    $s14 = "ck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"EHo" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}