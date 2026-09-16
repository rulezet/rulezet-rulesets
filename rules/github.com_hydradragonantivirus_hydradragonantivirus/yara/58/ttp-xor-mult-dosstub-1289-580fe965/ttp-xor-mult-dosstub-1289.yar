rule TTP_XOR_MULT_DOSStub_1289 {
  strings:
    $key_1289 = { 46 e1 [2] 32 f9 [2] 75 fb [2] 32 ea [2] 7c e6 [2] 70 ec [2] 67 e7 [2] 7c a9 [2] 41 }

  condition:
    any of them
}