rule TTP_XOR_MULT_DOSStub_7595 {
  strings:
    $key_7595 = { 21 fd [2] 55 e5 [2] 12 e7 [2] 55 f6 [2] 1b fa [2] 17 f0 [2] 00 fb [2] 1b b5 [2] 26 }

  condition:
    any of them
}