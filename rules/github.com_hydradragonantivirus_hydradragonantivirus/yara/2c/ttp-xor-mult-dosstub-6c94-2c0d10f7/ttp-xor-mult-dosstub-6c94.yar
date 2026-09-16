rule TTP_XOR_MULT_DOSStub_6c94 {
  strings:
    $key_6c94 = { 38 fc [2] 4c e4 [2] 0b e6 [2] 4c f7 [2] 02 fb [2] 0e f1 [2] 19 fa [2] 02 b4 [2] 3f }

  condition:
    any of them
}