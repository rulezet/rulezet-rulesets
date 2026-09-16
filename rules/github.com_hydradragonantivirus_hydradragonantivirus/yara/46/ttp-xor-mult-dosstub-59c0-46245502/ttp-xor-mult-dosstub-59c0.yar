rule TTP_XOR_MULT_DOSStub_59c0 {
  strings:
    $key_59c0 = { 0d a8 [2] 79 b0 [2] 3e b2 [2] 79 a3 [2] 37 af [2] 3b a5 [2] 2c ae [2] 37 e0 [2] 0a }

  condition:
    any of them
}