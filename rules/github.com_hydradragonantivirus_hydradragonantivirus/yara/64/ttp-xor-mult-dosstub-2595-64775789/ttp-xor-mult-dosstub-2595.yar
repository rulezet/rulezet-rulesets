rule TTP_XOR_MULT_DOSStub_2595 {
  strings:
    $key_2595 = { 71 fd [2] 05 e5 [2] 42 e7 [2] 05 f6 [2] 4b fa [2] 47 f0 [2] 50 fb [2] 4b b5 [2] 76 }

  condition:
    any of them
}