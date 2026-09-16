rule TTP_XOR_MULT_DOSStub_2280 {
  strings:
    $key_2280 = { 76 e8 [2] 02 f0 [2] 45 f2 [2] 02 e3 [2] 4c ef [2] 40 e5 [2] 57 ee [2] 4c a0 [2] 71 }

  condition:
    any of them
}