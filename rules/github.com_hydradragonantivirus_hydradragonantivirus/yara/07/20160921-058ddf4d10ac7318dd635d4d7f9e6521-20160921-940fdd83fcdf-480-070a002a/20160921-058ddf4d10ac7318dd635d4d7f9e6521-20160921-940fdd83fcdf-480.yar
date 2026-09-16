rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_940fdd83fcdf_480 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash3       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"
    hash4       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1  = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){r" ascii
    $s2  = "(){return \"Fv\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Pc\";})" ascii
    $s3  = "k(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";}" ascii
    $s4  = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Hs\";})" ascii
    $s5  = "n fuck(){return \"VMi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"X" ascii
    $s6  = "return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})" ascii
    $s7  = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s8  = "rn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(fu" ascii
    $s9  = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"KVh\";}" ascii
    $s10 = "(function fuck(){return \"Wn\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){re" ascii
    $s11 = "turn \"Xg\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(" ascii
    $s12 = " fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"P" ascii
    $s13 = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return" ascii
    $s14 = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"AU" ascii
    $s15 = "urn \"IOs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s16 = "turn \"Vf\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s17 = "unction fuck(){return \"GWo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){re" ascii
    $s18 = "eturn \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(f" ascii
    $s19 = " fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"R" ascii
    $s20 = "k(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xg\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}