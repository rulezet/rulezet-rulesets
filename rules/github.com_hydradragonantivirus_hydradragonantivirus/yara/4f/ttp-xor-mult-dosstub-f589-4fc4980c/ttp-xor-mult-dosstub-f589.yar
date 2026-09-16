rule TTP_XOR_MULT_DOSStub_f589 {
  strings:
    $key_f589 = { a1 e1 [2] d5 f9 [2] 92 fb [2] d5 ea [2] 9b e6 [2] 97 ec [2] 80 e7 [2] 9b a9 [2] a6 }

  condition:
    any of them
}