rule TTP_XOR_MULT_DOSStub_0c3a {
  strings:
    $key_0c3a = { 58 52 [2] 2c 4a [2] 6b 48 [2] 2c 59 [2] 62 55 [2] 6e 5f [2] 79 54 [2] 62 1a [2] 5f }

  condition:
    any of them
}