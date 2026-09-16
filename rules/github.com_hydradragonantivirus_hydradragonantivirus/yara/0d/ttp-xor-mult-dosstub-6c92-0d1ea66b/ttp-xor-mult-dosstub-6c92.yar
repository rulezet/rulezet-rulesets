rule TTP_XOR_MULT_DOSStub_6c92 {
  strings:
    $key_6c92 = { 38 fa [2] 4c e2 [2] 0b e0 [2] 4c f1 [2] 02 fd [2] 0e f7 [2] 19 fc [2] 02 b2 [2] 3f }

  condition:
    any of them
}