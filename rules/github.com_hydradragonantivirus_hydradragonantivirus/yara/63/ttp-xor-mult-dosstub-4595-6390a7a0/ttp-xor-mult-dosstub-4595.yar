rule TTP_XOR_MULT_DOSStub_4595 {
  strings:
    $key_4595 = { 11 fd [2] 65 e5 [2] 22 e7 [2] 65 f6 [2] 2b fa [2] 27 f0 [2] 30 fb [2] 2b b5 [2] 16 }

  condition:
    any of them
}