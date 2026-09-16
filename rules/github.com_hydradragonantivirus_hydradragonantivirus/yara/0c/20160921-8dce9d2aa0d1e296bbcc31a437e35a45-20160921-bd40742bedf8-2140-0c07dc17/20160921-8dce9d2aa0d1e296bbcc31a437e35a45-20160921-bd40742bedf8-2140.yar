rule _20160921_8dce9d2aa0d1e296bbcc31a437e35a45_20160921_bd40742bedf8_2140 {
  meta:
    description = "datamaliciousorder - from files 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "turn \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s2 = "{return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"DAa\";})" ascii
    $s3 = "fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"X" ascii
    $s4 = "tion fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){retur" ascii
    $s5 = "n \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s6 = "turn \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"PDf\";})()," ascii
    $s7 = "return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})" ascii
    $s8 = "ion fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s9 = "return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}