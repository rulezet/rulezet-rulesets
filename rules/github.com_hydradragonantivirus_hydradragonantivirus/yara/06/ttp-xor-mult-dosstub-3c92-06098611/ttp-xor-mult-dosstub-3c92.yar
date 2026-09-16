rule TTP_XOR_MULT_DOSStub_3c92 {
  strings:
    $key_3c92 = { 68 fa [2] 1c e2 [2] 5b e0 [2] 1c f1 [2] 52 fd [2] 5e f7 [2] 49 fc [2] 52 b2 [2] 6f }

  condition:
    any of them
}