rule TTP_XOR_MULT_DOSStub_2bc0 {
  strings:
    $key_2bc0 = { 7f a8 [2] 0b b0 [2] 4c b2 [2] 0b a3 [2] 45 af [2] 49 a5 [2] 5e ae [2] 45 e0 [2] 78 }

  condition:
    any of them
}