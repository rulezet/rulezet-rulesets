rule TTP_XOR_MULT_DOSStub_02c1 {
  strings:
    $key_02c1 = { 56 a9 [2] 22 b1 [2] 65 b3 [2] 22 a2 [2] 6c ae [2] 60 a4 [2] 77 af [2] 6c e1 [2] 51 }

  condition:
    any of them
}