rule TTP_XOR_MULT_DOSStub_4e95 {
  strings:
    $key_4e95 = { 1a fd [2] 6e e5 [2] 29 e7 [2] 6e f6 [2] 20 fa [2] 2c f0 [2] 3b fb [2] 20 b5 [2] 1d }

  condition:
    any of them
}