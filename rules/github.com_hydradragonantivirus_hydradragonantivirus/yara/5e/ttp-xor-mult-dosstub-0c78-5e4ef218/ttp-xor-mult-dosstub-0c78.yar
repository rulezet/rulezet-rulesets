rule TTP_XOR_MULT_DOSStub_0c78 {
  strings:
    $key_0c78 = { 58 10 [2] 2c 08 [2] 6b 0a [2] 2c 1b [2] 62 17 [2] 6e 1d [2] 79 16 [2] 62 58 [2] 5f }

  condition:
    any of them
}