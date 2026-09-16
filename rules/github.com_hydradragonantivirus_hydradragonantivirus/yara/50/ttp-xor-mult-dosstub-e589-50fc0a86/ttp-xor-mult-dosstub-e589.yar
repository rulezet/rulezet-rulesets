rule TTP_XOR_MULT_DOSStub_e589 {
  strings:
    $key_e589 = { b1 e1 [2] c5 f9 [2] 82 fb [2] c5 ea [2] 8b e6 [2] 87 ec [2] 90 e7 [2] 8b a9 [2] b6 }

  condition:
    any of them
}