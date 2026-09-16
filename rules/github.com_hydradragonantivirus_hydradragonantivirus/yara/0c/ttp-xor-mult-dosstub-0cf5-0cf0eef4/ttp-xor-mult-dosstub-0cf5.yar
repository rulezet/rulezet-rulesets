rule TTP_XOR_MULT_DOSStub_0cf5 {
  strings:
    $key_0cf5 = { 58 9d [2] 2c 85 [2] 6b 87 [2] 2c 96 [2] 62 9a [2] 6e 90 [2] 79 9b [2] 62 d5 [2] 5f }

  condition:
    any of them
}