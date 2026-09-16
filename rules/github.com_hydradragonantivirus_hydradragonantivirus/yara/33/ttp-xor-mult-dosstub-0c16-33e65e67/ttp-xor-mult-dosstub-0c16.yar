rule TTP_XOR_MULT_DOSStub_0c16 {
  strings:
    $key_0c16 = { 58 7e [2] 2c 66 [2] 6b 64 [2] 2c 75 [2] 62 79 [2] 6e 73 [2] 79 78 [2] 62 36 [2] 5f }

  condition:
    any of them
}