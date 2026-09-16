rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_bd40742bedf8_3031 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "Ai\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(functio" ascii
    $s2 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){ret" ascii
    $s3 = "return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s4 = "k(){return \"KVh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\"" ascii
    $s5 = "k(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\"" ascii
    $s6 = "GWo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(funct" ascii
    $s7 = "nction fuck(){return \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}