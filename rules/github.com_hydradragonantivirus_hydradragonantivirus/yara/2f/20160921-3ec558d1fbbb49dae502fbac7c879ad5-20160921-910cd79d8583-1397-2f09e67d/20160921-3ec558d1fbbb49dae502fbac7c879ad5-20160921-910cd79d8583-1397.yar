rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_910cd79d8583_1397 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash3       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"

  strings:
    $s1  = "uck(){return \"PDf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb" ascii
    $s2  = ",(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){" ascii
    $s3  = "){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})" ascii
    $s4  = "rn \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(fu" ascii
    $s5  = "(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";}" ascii
    $s6  = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retur" ascii
    $s7  = "tion fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s8  = "\"Mw\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(funct" ascii
    $s9  = "Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s10 = "function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){ret" ascii
    $s11 = " fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"I" ascii
    $s12 = "turn \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\";})()," ascii
    $s13 = "(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){r" ascii
    $s14 = "(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ug\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}