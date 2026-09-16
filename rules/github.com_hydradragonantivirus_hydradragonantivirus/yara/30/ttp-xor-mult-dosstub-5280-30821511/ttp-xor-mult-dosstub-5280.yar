rule TTP_XOR_MULT_DOSStub_5280 {
  strings:
    $key_5280 = { 06 e8 [2] 72 f0 [2] 35 f2 [2] 72 e3 [2] 3c ef [2] 30 e5 [2] 27 ee [2] 3c a0 [2] 01 }

  condition:
    any of them
}