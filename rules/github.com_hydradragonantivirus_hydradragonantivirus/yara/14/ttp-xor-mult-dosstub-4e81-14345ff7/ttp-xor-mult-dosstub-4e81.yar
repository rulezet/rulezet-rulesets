rule TTP_XOR_MULT_DOSStub_4e81 {
  strings:
    $key_4e81 = { 1a e9 [2] 6e f1 [2] 29 f3 [2] 6e e2 [2] 20 ee [2] 2c e4 [2] 3b ef [2] 20 a1 [2] 1d }

  condition:
    any of them
}