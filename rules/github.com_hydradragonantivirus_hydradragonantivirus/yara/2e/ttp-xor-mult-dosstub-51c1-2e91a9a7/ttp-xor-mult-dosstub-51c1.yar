rule TTP_XOR_MULT_DOSStub_51c1 {
  strings:
    $key_51c1 = { 05 a9 [2] 71 b1 [2] 36 b3 [2] 71 a2 [2] 3f ae [2] 33 a4 [2] 24 af [2] 3f e1 [2] 02 }

  condition:
    any of them
}