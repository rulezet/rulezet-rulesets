rule TTP_XOR_MULT_DOSStub_2e95 {
  strings:
    $key_2e95 = { 7a fd [2] 0e e5 [2] 49 e7 [2] 0e f6 [2] 40 fa [2] 4c f0 [2] 5b fb [2] 40 b5 [2] 7d }

  condition:
    any of them
}