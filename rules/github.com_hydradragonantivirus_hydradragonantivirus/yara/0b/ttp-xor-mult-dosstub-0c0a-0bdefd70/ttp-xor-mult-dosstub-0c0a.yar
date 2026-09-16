rule TTP_XOR_MULT_DOSStub_0c0a {
  strings:
    $key_0c0a = { 58 62 [2] 2c 7a [2] 6b 78 [2] 2c 69 [2] 62 65 [2] 6e 6f [2] 79 64 [2] 62 2a [2] 5f }

  condition:
    any of them
}