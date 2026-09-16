rule TTP_XOR_MULT_DOSStub_0c49 {
  strings:
    $key_0c49 = { 58 21 [2] 2c 39 [2] 6b 3b [2] 2c 2a [2] 62 26 [2] 6e 2c [2] 79 27 [2] 62 69 [2] 5f }

  condition:
    any of them
}