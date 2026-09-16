rule TTP_XOR_MULT_DOSStub_7695 {
  strings:
    $key_7695 = { 22 fd [2] 56 e5 [2] 11 e7 [2] 56 f6 [2] 18 fa [2] 14 f0 [2] 03 fb [2] 18 b5 [2] 25 }

  condition:
    any of them
}