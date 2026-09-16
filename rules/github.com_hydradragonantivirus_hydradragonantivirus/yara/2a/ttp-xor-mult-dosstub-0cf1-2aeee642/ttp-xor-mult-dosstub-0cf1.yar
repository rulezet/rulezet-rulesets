rule TTP_XOR_MULT_DOSStub_0cf1 {
  strings:
    $key_0cf1 = { 58 99 [2] 2c 81 [2] 6b 83 [2] 2c 92 [2] 62 9e [2] 6e 94 [2] 79 9f [2] 62 d1 [2] 5f }

  condition:
    any of them
}