rule TTP_XOR_MULT_DOSStub_3695 {
  strings:
    $key_3695 = { 62 fd [2] 16 e5 [2] 51 e7 [2] 16 f6 [2] 58 fa [2] 54 f0 [2] 43 fb [2] 58 b5 [2] 65 }

  condition:
    any of them
}