rule TTP_XOR_MULT_DOSStub_4ec1 {
  strings:
    $key_4ec1 = { 1a a9 [2] 6e b1 [2] 29 b3 [2] 6e a2 [2] 20 ae [2] 2c a4 [2] 3b af [2] 20 e1 [2] 1d }

  condition:
    any of them
}