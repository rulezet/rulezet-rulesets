rule TTP_XOR_MULT_DOSStub_5c92 {
  strings:
    $key_5c92 = { 08 fa [2] 7c e2 [2] 3b e0 [2] 7c f1 [2] 32 fd [2] 3e f7 [2] 29 fc [2] 32 b2 [2] 0f }

  condition:
    any of them
}