rule TTP_XOR_MULT_DOSStub_0c99 {
  strings:
    $key_0c99 = { 58 f1 [2] 2c e9 [2] 6b eb [2] 2c fa [2] 62 f6 [2] 6e fc [2] 79 f7 [2] 62 b9 [2] 5f }

  condition:
    any of them
}