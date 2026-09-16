rule TTP_XOR_MULT_DOSStub_5bc0 {
  strings:
    $key_5bc0 = { 0f a8 [2] 7b b0 [2] 3c b2 [2] 7b a3 [2] 35 af [2] 39 a5 [2] 2e ae [2] 35 e0 [2] 08 }

  condition:
    any of them
}