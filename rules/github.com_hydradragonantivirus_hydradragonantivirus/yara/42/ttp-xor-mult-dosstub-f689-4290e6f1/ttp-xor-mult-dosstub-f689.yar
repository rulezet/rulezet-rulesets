rule TTP_XOR_MULT_DOSStub_f689 {
  strings:
    $key_f689 = { a2 e1 [2] d6 f9 [2] 91 fb [2] d6 ea [2] 98 e6 [2] 94 ec [2] 83 e7 [2] 98 a9 [2] a5 }

  condition:
    any of them
}