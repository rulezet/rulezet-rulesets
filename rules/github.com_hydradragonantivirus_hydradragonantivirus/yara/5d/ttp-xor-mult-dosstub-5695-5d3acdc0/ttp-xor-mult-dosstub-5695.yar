rule TTP_XOR_MULT_DOSStub_5695 {
  strings:
    $key_5695 = { 02 fd [2] 76 e5 [2] 31 e7 [2] 76 f6 [2] 38 fa [2] 34 f0 [2] 23 fb [2] 38 b5 [2] 05 }

  condition:
    any of them
}