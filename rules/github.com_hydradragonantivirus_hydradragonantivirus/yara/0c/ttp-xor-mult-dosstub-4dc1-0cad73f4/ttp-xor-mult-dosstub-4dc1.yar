rule TTP_XOR_MULT_DOSStub_4dc1 {
  strings:
    $key_4dc1 = { 19 a9 [2] 6d b1 [2] 2a b3 [2] 6d a2 [2] 23 ae [2] 2f a4 [2] 38 af [2] 23 e1 [2] 1e }

  condition:
    any of them
}