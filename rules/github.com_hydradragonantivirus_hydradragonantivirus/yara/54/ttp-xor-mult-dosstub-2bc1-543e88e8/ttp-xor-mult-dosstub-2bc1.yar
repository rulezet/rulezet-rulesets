rule TTP_XOR_MULT_DOSStub_2bc1 {
  strings:
    $key_2bc1 = { 7f a9 [2] 0b b1 [2] 4c b3 [2] 0b a2 [2] 45 ae [2] 49 a4 [2] 5e af [2] 45 e1 [2] 78 }

  condition:
    any of them
}