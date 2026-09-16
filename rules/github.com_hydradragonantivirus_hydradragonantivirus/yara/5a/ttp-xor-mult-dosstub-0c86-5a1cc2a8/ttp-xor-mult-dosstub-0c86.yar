rule TTP_XOR_MULT_DOSStub_0c86 {
  strings:
    $key_0c86 = { 58 ee [2] 2c f6 [2] 6b f4 [2] 2c e5 [2] 62 e9 [2] 6e e3 [2] 79 e8 [2] 62 a6 [2] 5f }

  condition:
    any of them
}