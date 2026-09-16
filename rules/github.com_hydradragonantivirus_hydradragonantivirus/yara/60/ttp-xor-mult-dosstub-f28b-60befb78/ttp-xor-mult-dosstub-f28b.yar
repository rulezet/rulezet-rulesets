rule TTP_XOR_MULT_DOSStub_f28b {
  strings:
    $key_f28b = { a6 e3 [2] d2 fb [2] 95 f9 [2] d2 e8 [2] 9c e4 [2] 90 ee [2] 87 e5 [2] 9c ab [2] a1 }

  condition:
    any of them
}