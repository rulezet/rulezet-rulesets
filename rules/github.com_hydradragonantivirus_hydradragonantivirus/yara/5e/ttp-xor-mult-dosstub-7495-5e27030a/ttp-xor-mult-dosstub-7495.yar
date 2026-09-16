rule TTP_XOR_MULT_DOSStub_7495 {
  strings:
    $key_7495 = { 20 fd [2] 54 e5 [2] 13 e7 [2] 54 f6 [2] 1a fa [2] 16 f0 [2] 01 fb [2] 1a b5 [2] 27 }

  condition:
    any of them
}