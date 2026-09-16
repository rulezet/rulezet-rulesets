rule TTP_XOR_MULT_DOSStub_5c95 {
  strings:
    $key_5c95 = { 08 fd [2] 7c e5 [2] 3b e7 [2] 7c f6 [2] 32 fa [2] 3e f0 [2] 29 fb [2] 32 b5 [2] 0f }

  condition:
    any of them
}