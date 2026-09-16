rule TTP_XOR_MULT_DOSStub_0c04 {
  strings:
    $key_0c04 = { 58 6c [2] 2c 74 [2] 6b 76 [2] 2c 67 [2] 62 6b [2] 6e 61 [2] 79 6a [2] 62 24 [2] 5f }

  condition:
    any of them
}