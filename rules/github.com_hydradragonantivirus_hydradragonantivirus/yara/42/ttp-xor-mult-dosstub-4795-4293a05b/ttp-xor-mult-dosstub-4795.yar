rule TTP_XOR_MULT_DOSStub_4795 {
  strings:
    $key_4795 = { 13 fd [2] 67 e5 [2] 20 e7 [2] 67 f6 [2] 29 fa [2] 25 f0 [2] 32 fb [2] 29 b5 [2] 14 }

  condition:
    any of them
}