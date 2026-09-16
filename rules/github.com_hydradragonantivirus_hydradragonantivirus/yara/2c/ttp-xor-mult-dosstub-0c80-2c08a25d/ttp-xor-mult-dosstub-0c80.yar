rule TTP_XOR_MULT_DOSStub_0c80 {
  strings:
    $key_0c80 = { 58 e8 [2] 2c f0 [2] 6b f2 [2] 2c e3 [2] 62 ef [2] 6e e5 [2] 79 ee [2] 62 a0 [2] 5f }

  condition:
    any of them
}