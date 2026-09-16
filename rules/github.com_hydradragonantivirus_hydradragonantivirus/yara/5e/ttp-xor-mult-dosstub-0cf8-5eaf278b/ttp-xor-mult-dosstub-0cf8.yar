rule TTP_XOR_MULT_DOSStub_0cf8 {
  strings:
    $key_0cf8 = { 58 90 [2] 2c 88 [2] 6b 8a [2] 2c 9b [2] 62 97 [2] 6e 9d [2] 79 96 [2] 62 d8 [2] 5f }

  condition:
    any of them
}