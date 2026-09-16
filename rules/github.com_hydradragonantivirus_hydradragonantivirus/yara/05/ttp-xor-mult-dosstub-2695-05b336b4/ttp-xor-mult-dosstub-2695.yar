rule TTP_XOR_MULT_DOSStub_2695 {
  strings:
    $key_2695 = { 72 fd [2] 06 e5 [2] 41 e7 [2] 06 f6 [2] 48 fa [2] 44 f0 [2] 53 fb [2] 48 b5 [2] 75 }

  condition:
    any of them
}