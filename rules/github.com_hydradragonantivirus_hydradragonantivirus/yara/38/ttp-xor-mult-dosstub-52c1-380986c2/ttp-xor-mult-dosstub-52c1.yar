rule TTP_XOR_MULT_DOSStub_52c1 {
  strings:
    $key_52c1 = { 06 a9 [2] 72 b1 [2] 35 b3 [2] 72 a2 [2] 3c ae [2] 30 a4 [2] 27 af [2] 3c e1 [2] 01 }

  condition:
    any of them
}