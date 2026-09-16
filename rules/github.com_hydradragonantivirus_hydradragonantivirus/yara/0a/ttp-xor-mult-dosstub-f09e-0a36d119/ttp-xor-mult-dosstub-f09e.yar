rule TTP_XOR_MULT_DOSStub_f09e {
  strings:
    $key_f09e = { a4 f6 [2] d0 ee [2] 97 ec [2] d0 fd [2] 9e f1 [2] 92 fb [2] 85 f0 [2] 9e be [2] a3 }

  condition:
    any of them
}