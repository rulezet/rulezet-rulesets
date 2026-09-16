rule TTP_XOR_MULT_DOSStub_35c1 {
  strings:
    $key_35c1 = { 61 a9 [2] 15 b1 [2] 52 b3 [2] 15 a2 [2] 5b ae [2] 57 a4 [2] 40 af [2] 5b e1 [2] 66 }

  condition:
    any of them
}