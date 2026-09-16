rule _20160921_64060d97e498db57bf68dbb08be86bba_20160921_8acd2bde0828_2483 {
  meta:
    description = "datamaliciousorder - from files 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash2       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"

  strings:
    $s1 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s2 = "){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"KVh\";" ascii
    $s3 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){retu" ascii
    $s4 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})()" ascii
    $s5 = "Os\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(functio" ascii
    $s6 = "{return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})" ascii
    $s7 = "x\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function" ascii
    $s8 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}