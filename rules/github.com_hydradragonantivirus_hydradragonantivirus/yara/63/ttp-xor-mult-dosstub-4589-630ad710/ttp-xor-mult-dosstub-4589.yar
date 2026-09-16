rule TTP_XOR_MULT_DOSStub_4589 {
  strings:
    $key_4589 = { 11 e1 [2] 65 f9 [2] 22 fb [2] 65 ea [2] 2b e6 [2] 27 ec [2] 30 e7 [2] 2b a9 [2] 16 }

  condition:
    any of them
}