rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_589 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash4       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"

  strings:
    $s1  = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function f" ascii
    $s2  = "fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py" ascii
    $s3  = "eturn \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s4  = "urn \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(f" ascii
    $s5  = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s6  = "\"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s7  = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s8  = "k(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";}" ascii
    $s9  = "fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml" ascii
    $s10 = "fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py" ascii
    $s11 = "ction fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s12 = "return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(" ascii
    $s13 = "(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";}" ascii
    $s14 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s15 = "y\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function" ascii
    $s16 = "(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";" ascii
    $s17 = " fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe" ascii
    $s18 = "rn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s19 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){r" ascii
    $s20 = "n \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}