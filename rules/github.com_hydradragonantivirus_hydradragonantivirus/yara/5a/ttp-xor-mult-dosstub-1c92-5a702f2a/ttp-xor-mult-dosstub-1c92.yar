rule TTP_XOR_MULT_DOSStub_1c92 {
  strings:
    $key_1c92 = { 48 fa [2] 3c e2 [2] 7b e0 [2] 3c f1 [2] 72 fd [2] 7e f7 [2] 69 fc [2] 72 b2 [2] 4f }

  condition:
    any of them
}