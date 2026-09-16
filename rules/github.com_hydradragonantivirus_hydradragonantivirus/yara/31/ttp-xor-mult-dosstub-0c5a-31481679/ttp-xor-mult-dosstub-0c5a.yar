rule TTP_XOR_MULT_DOSStub_0c5a {
  strings:
    $key_0c5a = { 58 32 [2] 2c 2a [2] 6b 28 [2] 2c 39 [2] 62 35 [2] 6e 3f [2] 79 34 [2] 62 7a [2] 5f }

  condition:
    any of them
}