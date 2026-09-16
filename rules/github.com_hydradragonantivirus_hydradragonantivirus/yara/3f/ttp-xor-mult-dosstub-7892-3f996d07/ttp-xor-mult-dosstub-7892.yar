rule TTP_XOR_MULT_DOSStub_7892 {
  strings:
    $key_7892 = { 2c fa [2] 58 e2 [2] 1f e0 [2] 58 f1 [2] 16 fd [2] 1a f7 [2] 0d fc [2] 16 b2 [2] 2b }

  condition:
    any of them
}