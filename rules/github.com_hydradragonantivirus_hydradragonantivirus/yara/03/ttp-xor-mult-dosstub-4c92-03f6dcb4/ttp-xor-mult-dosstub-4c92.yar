rule TTP_XOR_MULT_DOSStub_4c92 {
  strings:
    $key_4c92 = { 18 fa [2] 6c e2 [2] 2b e0 [2] 6c f1 [2] 22 fd [2] 2e f7 [2] 39 fc [2] 22 b2 [2] 1f }

  condition:
    any of them
}