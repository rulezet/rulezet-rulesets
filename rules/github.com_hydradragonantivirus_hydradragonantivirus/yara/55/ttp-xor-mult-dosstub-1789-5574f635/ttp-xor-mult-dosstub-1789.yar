rule TTP_XOR_MULT_DOSStub_1789 {
  strings:
    $key_1789 = { 43 e1 [2] 37 f9 [2] 70 fb [2] 37 ea [2] 79 e6 [2] 75 ec [2] 62 e7 [2] 79 a9 [2] 44 }

  condition:
    any of them
}