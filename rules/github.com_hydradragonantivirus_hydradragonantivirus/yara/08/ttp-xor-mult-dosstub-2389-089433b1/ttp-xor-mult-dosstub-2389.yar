rule TTP_XOR_MULT_DOSStub_2389 {
  strings:
    $key_2389 = { 77 e1 [2] 03 f9 [2] 44 fb [2] 03 ea [2] 4d e6 [2] 41 ec [2] 56 e7 [2] 4d a9 [2] 70 }

  condition:
    any of them
}