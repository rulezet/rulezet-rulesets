rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_5a42d0e1880d_1642 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash3       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash4       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash5       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash6       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"
    hash7       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"
    hash8       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1  = "\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XHj\";})(),(function f" ascii
    $s2  = "eturn \"Zy\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ot\";})(),(f" ascii
    $s3  = "turn \"Vf\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(f" ascii
    $s4  = "n \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Xg\";})(),(func" ascii
    $s5  = "\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function " ascii
    $s6  = "fuck(){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Ar" ascii
    $s7  = "k(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";" ascii
    $s8  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Z" ascii
    $s9  = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s10 = "{return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(" ascii
    $s11 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}