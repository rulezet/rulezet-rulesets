rule TTP_XOR_MULT_DOSStub_5489 {
  strings:
    $key_5489 = { 00 e1 [2] 74 f9 [2] 33 fb [2] 74 ea [2] 3a e6 [2] 36 ec [2] 21 e7 [2] 3a a9 [2] 07 }

  condition:
    any of them
}