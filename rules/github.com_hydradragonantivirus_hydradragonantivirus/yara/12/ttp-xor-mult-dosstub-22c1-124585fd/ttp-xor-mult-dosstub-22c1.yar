rule TTP_XOR_MULT_DOSStub_22c1 {
  strings:
    $key_22c1 = { 76 a9 [2] 02 b1 [2] 45 b3 [2] 02 a2 [2] 4c ae [2] 40 a4 [2] 57 af [2] 4c e1 [2] 71 }

  condition:
    any of them
}