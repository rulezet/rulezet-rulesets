rule TTP_XOR_MULT_DOSStub_7598 {
  strings:
    $key_7598 = { 21 f0 [2] 55 e8 [2] 12 ea [2] 55 fb [2] 1b f7 [2] 17 fd [2] 00 f6 [2] 1b b8 [2] 26 }

  condition:
    any of them
}