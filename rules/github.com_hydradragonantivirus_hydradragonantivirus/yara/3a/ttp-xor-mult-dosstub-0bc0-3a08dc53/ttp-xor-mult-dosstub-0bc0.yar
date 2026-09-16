rule TTP_XOR_MULT_DOSStub_0bc0 {
  strings:
    $key_0bc0 = { 5f a8 [2] 2b b0 [2] 6c b2 [2] 2b a3 [2] 65 af [2] 69 a5 [2] 7e ae [2] 65 e0 [2] 58 }

  condition:
    any of them
}