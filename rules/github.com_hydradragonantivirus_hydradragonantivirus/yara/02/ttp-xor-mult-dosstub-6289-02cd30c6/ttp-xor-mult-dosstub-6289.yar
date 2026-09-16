rule TTP_XOR_MULT_DOSStub_6289 {
  strings:
    $key_6289 = { 36 e1 [2] 42 f9 [2] 05 fb [2] 42 ea [2] 0c e6 [2] 00 ec [2] 17 e7 [2] 0c a9 [2] 31 }

  condition:
    any of them
}