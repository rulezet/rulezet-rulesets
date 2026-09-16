rule TTP_XOR_MULT_DOSStub_7c92 {
  strings:
    $key_7c92 = { 28 fa [2] 5c e2 [2] 1b e0 [2] 5c f1 [2] 12 fd [2] 1e f7 [2] 09 fc [2] 12 b2 [2] 2f }

  condition:
    any of them
}