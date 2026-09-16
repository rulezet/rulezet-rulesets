rule _20160921_063094039ef79437a260d3dde960797a_20160921_4031e49cbb76_4252 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"

  strings:
    $s1 = "(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})" ascii
    $s2 = " \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(func" ascii
    $s3 = "u\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"KVh\";})(),(function" ascii
    $s4 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s5 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}