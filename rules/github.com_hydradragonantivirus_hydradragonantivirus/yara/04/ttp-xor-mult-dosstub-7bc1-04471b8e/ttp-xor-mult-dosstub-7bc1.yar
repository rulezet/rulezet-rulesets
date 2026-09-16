rule TTP_XOR_MULT_DOSStub_7bc1 {
  strings:
    $key_7bc1 = { 2f a9 [2] 5b b1 [2] 1c b3 [2] 5b a2 [2] 15 ae [2] 19 a4 [2] 0e af [2] 15 e1 [2] 28 }

  condition:
    any of them
}