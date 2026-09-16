rule TTP_XOR_MULT_DOSStub_1595 {
  strings:
    $key_1595 = { 41 fd [2] 35 e5 [2] 72 e7 [2] 35 f6 [2] 7b fa [2] 77 f0 [2] 60 fb [2] 7b b5 [2] 46 }

  condition:
    any of them
}