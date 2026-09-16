rule TTP_XOR_MULT_DOSStub_7489 {
  strings:
    $key_7489 = { 20 e1 [2] 54 f9 [2] 13 fb [2] 54 ea [2] 1a e6 [2] 16 ec [2] 01 e7 [2] 1a a9 [2] 27 }

  condition:
    any of them
}