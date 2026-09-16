rule TTP_XOR_MULT_DOSStub_4dc0 {
  strings:
    $key_4dc0 = { 19 a8 [2] 6d b0 [2] 2a b2 [2] 6d a3 [2] 23 af [2] 2f a5 [2] 38 ae [2] 23 e0 [2] 1e }

  condition:
    any of them
}