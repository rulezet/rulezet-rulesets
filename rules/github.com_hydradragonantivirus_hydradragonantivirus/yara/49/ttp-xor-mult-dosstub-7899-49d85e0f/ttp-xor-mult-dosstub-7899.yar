rule TTP_XOR_MULT_DOSStub_7899 {
  strings:
    $key_7899 = { 2c f1 [2] 58 e9 [2] 1f eb [2] 58 fa [2] 16 f6 [2] 1a fc [2] 0d f7 [2] 16 b9 [2] 2b }

  condition:
    any of them
}