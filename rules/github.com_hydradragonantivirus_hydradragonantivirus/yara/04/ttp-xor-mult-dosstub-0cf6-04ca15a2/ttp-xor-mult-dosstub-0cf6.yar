rule TTP_XOR_MULT_DOSStub_0cf6 {
  strings:
    $key_0cf6 = { 58 9e [2] 2c 86 [2] 6b 84 [2] 2c 95 [2] 62 99 [2] 6e 93 [2] 79 98 [2] 62 d6 [2] 5f }

  condition:
    any of them
}