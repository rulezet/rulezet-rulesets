rule TTP_XOR_MULT_DOSStub_f280 {
  strings:
    $key_f280 = { a6 e8 [2] d2 f0 [2] 95 f2 [2] d2 e3 [2] 9c ef [2] 90 e5 [2] 87 ee [2] 9c a0 [2] a1 }

  condition:
    any of them
}