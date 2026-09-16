rule TTP_XOR_MULT_DOSStub_f089 {
  strings:
    $key_f089 = { a4 e1 [2] d0 f9 [2] 97 fb [2] d0 ea [2] 9e e6 [2] 92 ec [2] 85 e7 [2] 9e a9 [2] a3 }

  condition:
    any of them
}