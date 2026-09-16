rule _20160921_26653257e0da59c861fc658d3bccdafd_20160921_dd3003e8f162_1190 {
  meta:
    description = "datamaliciousorder - from files 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash2       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1  = "{return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s2  = " fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"P" ascii
    $s3  = "k(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";" ascii
    $s4  = "return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(" ascii
    $s5  = "\"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(func" ascii
    $s6  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function f" ascii
    $s7  = "n \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fun" ascii
    $s8  = "ck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd" ascii
    $s9  = "Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s10 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return" ascii
    $s11 = "(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(" ascii
    $s12 = "eturn \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})()," ascii
    $s13 = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){r" ascii
    $s14 = "eturn \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})()" ascii
    $s15 = "(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})" ascii
    $s16 = "on fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}