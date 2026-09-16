rule _20160921_4809ff2679793c2b9af03e18ec3702ef_20160921_64060d97e498_1578 {
  meta:
    description = "datamaliciousorder - from files 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_64060d97e498db57bf68dbb08be86bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash2       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"

  strings:
    $s1  = " fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"" ascii
    $s2  = "turn \"MUs\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3  = "return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(" ascii
    $s4  = "function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s5  = "fuck(){return \"CTm\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg" ascii
    $s6  = "u\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s7  = "){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})" ascii
    $s8  = " \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(func" ascii
    $s9  = "k(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";}" ascii
    $s10 = "fuck(){return \"EHo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GN" ascii
    $s11 = "\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s12 = "turn \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}