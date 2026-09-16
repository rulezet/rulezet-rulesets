rule TTP_XOR_MULT_DOSStub_f789 {
  strings:
    $key_f789 = { a3 e1 [2] d7 f9 [2] 90 fb [2] d7 ea [2] 99 e6 [2] 95 ec [2] 82 e7 [2] 99 a9 [2] a4 }

  condition:
    any of them
}