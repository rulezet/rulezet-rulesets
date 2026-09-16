rule TTP_XOR_MULT_DOSStub_0cf4 {
  strings:
    $key_0cf4 = { 58 9c [2] 2c 84 [2] 6b 86 [2] 2c 97 [2] 62 9b [2] 6e 91 [2] 79 9a [2] 62 d4 [2] 5f }

  condition:
    any of them
}