rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_1410ebf3977c_4343 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_70b567ca258b3c505e14f3c712366f09.js, 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash3       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash4       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash5       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash6       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash7       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"
    hash8       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash9       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash10      = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "n \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(fun" ascii
    $s2 = "ion fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return " ascii
    $s3 = "h\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(functio" ascii
    $s4 = "){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(" ascii
    $s5 = "nction fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}