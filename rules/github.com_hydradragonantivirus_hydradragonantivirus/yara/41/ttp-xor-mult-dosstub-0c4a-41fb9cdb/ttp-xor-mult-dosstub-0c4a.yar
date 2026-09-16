rule TTP_XOR_MULT_DOSStub_0c4a {
  strings:
    $key_0c4a = { 58 22 [2] 2c 3a [2] 6b 38 [2] 2c 29 [2] 62 25 [2] 6e 2f [2] 79 24 [2] 62 6a [2] 5f }

  condition:
    any of them
}