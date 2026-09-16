rule TTP_XOR_MULT_DOSStub_2c95 {
  strings:
    $key_2c95 = { 78 fd [2] 0c e5 [2] 4b e7 [2] 0c f6 [2] 42 fa [2] 4e f0 [2] 59 fb [2] 42 b5 [2] 7f }

  condition:
    any of them
}