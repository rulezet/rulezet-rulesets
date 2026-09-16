rule TTP_XOR_MULT_DOSStub_7bc0 {
  strings:
    $key_7bc0 = { 2f a8 [2] 5b b0 [2] 1c b2 [2] 5b a3 [2] 15 af [2] 19 a5 [2] 0e ae [2] 15 e0 [2] 28 }

  condition:
    any of them
}