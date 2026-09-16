rule TTP_XOR_MULT_DOSStub_3289 {
  strings:
    $key_3289 = { 66 e1 [2] 12 f9 [2] 55 fb [2] 12 ea [2] 5c e6 [2] 50 ec [2] 47 e7 [2] 5c a9 [2] 61 }

  condition:
    any of them
}