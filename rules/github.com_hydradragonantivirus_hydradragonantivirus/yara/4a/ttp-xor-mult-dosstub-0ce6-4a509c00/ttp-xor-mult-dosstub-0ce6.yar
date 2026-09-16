rule TTP_XOR_MULT_DOSStub_0ce6 {
  strings:
    $key_0ce6 = { 58 8e [2] 2c 96 [2] 6b 94 [2] 2c 85 [2] 62 89 [2] 6e 83 [2] 79 88 [2] 62 c6 [2] 5f }

  condition:
    any of them
}