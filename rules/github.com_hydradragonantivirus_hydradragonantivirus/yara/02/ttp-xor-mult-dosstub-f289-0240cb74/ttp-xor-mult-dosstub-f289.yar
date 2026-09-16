rule TTP_XOR_MULT_DOSStub_f289 {
  strings:
    $key_f289 = { a6 e1 [2] d2 f9 [2] 95 fb [2] d2 ea [2] 9c e6 [2] 90 ec [2] 87 e7 [2] 9c a9 [2] a1 }

  condition:
    any of them
}