rule TTP_XOR_MULT_DOSStub_f593 {
  strings:
    $key_f593 = { a1 fb [2] d5 e3 [2] 92 e1 [2] d5 f0 [2] 9b fc [2] 97 f6 [2] 80 fd [2] 9b b3 [2] a6 }

  condition:
    any of them
}