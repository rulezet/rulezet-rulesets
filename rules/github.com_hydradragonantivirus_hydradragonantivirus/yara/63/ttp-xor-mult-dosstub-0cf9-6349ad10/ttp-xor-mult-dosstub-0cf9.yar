rule TTP_XOR_MULT_DOSStub_0cf9 {
  strings:
    $key_0cf9 = { 58 91 [2] 2c 89 [2] 6b 8b [2] 2c 9a [2] 62 96 [2] 6e 9c [2] 79 97 [2] 62 d9 [2] 5f }

  condition:
    any of them
}