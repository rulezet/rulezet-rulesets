rule TTP_XOR_MULT_DOSStub_6bc0 {
  strings:
    $key_6bc0 = { 3f a8 [2] 4b b0 [2] 0c b2 [2] 4b a3 [2] 05 af [2] 09 a5 [2] 1e ae [2] 05 e0 [2] 38 }

  condition:
    any of them
}