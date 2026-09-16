rule TTP_XOR_MULT_DOSStub_c189 {
  strings:
    $key_c189 = { 95 e1 [2] e1 f9 [2] a6 fb [2] e1 ea [2] af e6 [2] a3 ec [2] b4 e7 [2] af a9 [2] 92 }

  condition:
    any of them
}