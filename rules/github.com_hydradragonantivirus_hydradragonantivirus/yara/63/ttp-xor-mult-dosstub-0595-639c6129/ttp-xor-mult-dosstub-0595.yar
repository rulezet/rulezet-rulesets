rule TTP_XOR_MULT_DOSStub_0595 {
  strings:
    $key_0595 = { 51 fd [2] 25 e5 [2] 62 e7 [2] 25 f6 [2] 6b fa [2] 67 f0 [2] 70 fb [2] 6b b5 [2] 56 }

  condition:
    any of them
}