rule TTP_XOR_MULT_DOSStub_2589 {
  strings:
    $key_2589 = { 71 e1 [2] 05 f9 [2] 42 fb [2] 05 ea [2] 4b e6 [2] 47 ec [2] 50 e7 [2] 4b a9 [2] 76 }

  condition:
    any of them
}