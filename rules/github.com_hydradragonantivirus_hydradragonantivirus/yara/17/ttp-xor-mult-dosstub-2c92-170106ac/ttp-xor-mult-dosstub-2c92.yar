rule TTP_XOR_MULT_DOSStub_2c92 {
  strings:
    $key_2c92 = { 78 fa [2] 0c e2 [2] 4b e0 [2] 0c f1 [2] 42 fd [2] 4e f7 [2] 59 fc [2] 42 b2 [2] 7f }

  condition:
    any of them
}