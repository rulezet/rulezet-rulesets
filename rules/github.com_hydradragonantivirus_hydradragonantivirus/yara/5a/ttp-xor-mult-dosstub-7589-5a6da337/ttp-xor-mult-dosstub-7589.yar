rule TTP_XOR_MULT_DOSStub_7589 {
  strings:
    $key_7589 = { 21 e1 [2] 55 f9 [2] 12 fb [2] 55 ea [2] 1b e6 [2] 17 ec [2] 00 e7 [2] 1b a9 [2] 26 }

  condition:
    any of them
}