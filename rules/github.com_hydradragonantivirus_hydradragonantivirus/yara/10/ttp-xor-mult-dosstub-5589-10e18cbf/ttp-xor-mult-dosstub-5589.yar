rule TTP_XOR_MULT_DOSStub_5589 {
  strings:
    $key_5589 = { 01 e1 [2] 75 f9 [2] 32 fb [2] 75 ea [2] 3b e6 [2] 37 ec [2] 20 e7 [2] 3b a9 [2] 06 }

  condition:
    any of them
}