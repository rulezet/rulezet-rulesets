rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_f926399cbb63_521 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1  = "rn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s2  = "d\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function" ascii
    $s3  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"DWe\";})()" ascii
    $s4  = "\"Vf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s5  = "n fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"" ascii
    $s6  = "unction fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){retu" ascii
    $s7  = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw" ascii
    $s8  = "urn \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s9  = "(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s10 = "turn \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})()," ascii
    $s11 = "(function fuck(){return \"Oh\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii
    $s12 = " fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZW" ascii
    $s13 = "k(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";" ascii
    $s14 = "ion fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s15 = " \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s16 = "\"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(func" ascii
    $s17 = "urn \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(" ascii
    $s18 = "urn \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})()," ascii
    $s19 = " fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"" ascii
    $s20 = "n fuck(){return \"XFd\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}