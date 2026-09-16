rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_a8c002f684df_145 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"

  strings:
    $s1  = " \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s2  = "(){return \"IOs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s3  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IP" ascii
    $s4  = "on fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"" ascii
    $s5  = "(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"AUx\";})" ascii
    $s6  = "rn \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s7  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){" ascii
    $s8  = "y\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functio" ascii
    $s9  = ",(function fuck(){return \"We\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii
    $s10 = "unction fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s11 = "urn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(" ascii
    $s12 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(functio" ascii
    $s13 = "k(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\"" ascii
    $s14 = "(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){re" ascii
    $s15 = "turn \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Yk\";})(),(f" ascii
    $s16 = "rn \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s17 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return" ascii
    $s18 = "on fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return " ascii
    $s19 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){ret" ascii
    $s20 = "k(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"UOe" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}