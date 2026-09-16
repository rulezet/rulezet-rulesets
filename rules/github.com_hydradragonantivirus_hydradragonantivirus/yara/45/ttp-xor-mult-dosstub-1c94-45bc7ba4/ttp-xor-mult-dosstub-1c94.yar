rule TTP_XOR_MULT_DOSStub_1c94 {
  strings:
    $key_1c94 = { 48 fc [2] 3c e4 [2] 7b e6 [2] 3c f7 [2] 72 fb [2] 7e f1 [2] 69 fa [2] 72 b4 [2] 4f }

  condition:
    any of them
}