rule TTP_XOR_MULT_DOSStub_0cbc {
  strings:
    $key_0cbc = { 58 d4 [2] 2c cc [2] 6b ce [2] 2c df [2] 62 d3 [2] 6e d9 [2] 79 d2 [2] 62 9c [2] 5f }

  condition:
    any of them
}