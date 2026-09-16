rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_3a2902eaca0b_3395 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_3a2902eaca0b2b91120958418b46c844.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"

  strings:
    $s1 = "Pu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function" ascii
    $s2 = "\"Ar\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii
    $s3 = "ction fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s4 = "on fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s5 = "turn \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s6 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}