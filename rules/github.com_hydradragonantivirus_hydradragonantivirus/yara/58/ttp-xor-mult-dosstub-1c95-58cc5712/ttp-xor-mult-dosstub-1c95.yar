rule TTP_XOR_MULT_DOSStub_1c95 {
  strings:
    $key_1c95 = { 48 fd [2] 3c e5 [2] 7b e7 [2] 3c f6 [2] 72 fa [2] 7e f0 [2] 69 fb [2] 72 b5 [2] 4f }

  condition:
    any of them
}