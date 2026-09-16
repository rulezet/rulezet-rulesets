rule TTP_XOR_MULT_DOSStub_1393 {
  strings:
    $key_1393 = { 47 fb [2] 33 e3 [2] 74 e1 [2] 33 f0 [2] 7d fc [2] 71 f6 [2] 66 fd [2] 7d b3 [2] 40 }

  condition:
    any of them
}