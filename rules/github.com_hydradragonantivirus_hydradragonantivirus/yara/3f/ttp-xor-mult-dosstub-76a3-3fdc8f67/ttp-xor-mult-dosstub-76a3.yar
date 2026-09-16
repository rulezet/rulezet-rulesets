rule TTP_XOR_MULT_DOSStub_76a3 {
  strings:
    $key_76a3 = { 22 cb [2] 56 d3 [2] 11 d1 [2] 56 c0 [2] 18 cc [2] 14 c6 [2] 03 cd [2] 18 83 [2] 25 }

  condition:
    any of them
}