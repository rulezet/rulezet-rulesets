rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_4031e49cbb76_3496 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash3       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fu" ascii
    $s2 = "){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s3 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(functi" ascii
    $s4 = "unction fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){ret" ascii
    $s5 = "return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MUs\";})()" ascii
    $s6 = " \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}