rule TTP_XOR_MULT_DOSStub_0c12 {
  strings:
    $key_0c12 = { 58 7a [2] 2c 62 [2] 6b 60 [2] 2c 71 [2] 62 7d [2] 6e 77 [2] 79 7c [2] 62 32 [2] 5f }

  condition:
    any of them
}