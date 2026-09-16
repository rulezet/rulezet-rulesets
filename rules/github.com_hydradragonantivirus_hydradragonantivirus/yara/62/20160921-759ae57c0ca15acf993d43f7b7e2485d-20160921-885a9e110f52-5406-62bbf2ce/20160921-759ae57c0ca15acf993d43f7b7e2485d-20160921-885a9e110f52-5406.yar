rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_885a9e110f52_5406 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash3       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash4       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "ck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\"" ascii
    $s2 = "})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck" ascii
    $s3 = "\"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s4 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return" ascii
    $s5 = "urn \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}