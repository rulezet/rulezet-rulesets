rule TTP_XOR_MULT_DOSStub_0c7f {
  strings:
    $key_0c7f = { 58 17 [2] 2c 0f [2] 6b 0d [2] 2c 1c [2] 62 10 [2] 6e 1a [2] 79 11 [2] 62 5f [2] 5f }

  condition:
    any of them
}