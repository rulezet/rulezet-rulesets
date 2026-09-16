rule TTP_XOR_MULT_DOSStub_79c1 {
  strings:
    $key_79c1 = { 2d a9 [2] 59 b1 [2] 1e b3 [2] 59 a2 [2] 17 ae [2] 1b a4 [2] 0c af [2] 17 e1 [2] 2a }

  condition:
    any of them
}