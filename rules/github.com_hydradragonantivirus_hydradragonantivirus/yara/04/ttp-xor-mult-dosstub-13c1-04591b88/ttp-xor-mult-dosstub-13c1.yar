rule TTP_XOR_MULT_DOSStub_13c1 {
  strings:
    $key_13c1 = { 47 a9 [2] 33 b1 [2] 74 b3 [2] 33 a2 [2] 7d ae [2] 71 a4 [2] 66 af [2] 7d e1 [2] 40 }

  condition:
    any of them
}