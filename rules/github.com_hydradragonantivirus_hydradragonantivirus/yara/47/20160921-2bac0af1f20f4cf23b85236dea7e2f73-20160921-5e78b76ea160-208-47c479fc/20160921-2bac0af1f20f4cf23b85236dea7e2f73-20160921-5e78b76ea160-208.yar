rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_5e78b76ea160_208 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_dc67677da64e0c03fb55538663264839.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash3       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash4       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash5       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"
    hash6       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1  = "n fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s2  = "Il\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3  = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){" ascii
    $s4  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"VMi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s5  = "tion fuck(){return \"Zy\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6  = "){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";}" ascii
    $s7  = "})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Zy\";})(),(function fuck" ascii
    $s8  = "\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s9  = "){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DWe\";})" ascii
    $s10 = "\"Za\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s11 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retu" ascii
    $s12 = ";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s13 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo\";" ascii
    $s14 = " fuck(){return \"Xg\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Dc" ascii
    $s15 = " fuck(){return \"Mw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw" ascii
    $s16 = "x\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(functio" ascii
    $s17 = "\"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(functi" ascii
    $s18 = "k(){return \"Oh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Nm\";}" ascii
    $s19 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Et\";})(" ascii
    $s20 = "fuck(){return \"UXf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}