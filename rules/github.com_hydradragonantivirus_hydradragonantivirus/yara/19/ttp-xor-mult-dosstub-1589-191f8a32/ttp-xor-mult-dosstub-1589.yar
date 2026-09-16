rule TTP_XOR_MULT_DOSStub_1589 {
  strings:
    $key_1589 = { 41 e1 [2] 35 f9 [2] 72 fb [2] 35 ea [2] 7b e6 [2] 77 ec [2] 60 e7 [2] 7b a9 [2] 46 }

  condition:
    any of them
}