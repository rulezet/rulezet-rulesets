rule TTP_XOR_MULT_DOSStub_4495 {
  strings:
    $key_4495 = { 10 fd [2] 64 e5 [2] 23 e7 [2] 64 f6 [2] 2a fa [2] 26 f0 [2] 31 fb [2] 2a b5 [2] 17 }

  condition:
    any of them
}