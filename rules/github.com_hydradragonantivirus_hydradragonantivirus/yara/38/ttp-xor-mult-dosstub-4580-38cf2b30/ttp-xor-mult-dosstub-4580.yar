rule TTP_XOR_MULT_DOSStub_4580 {
  strings:
    $key_4580 = { 11 e8 [2] 65 f0 [2] 22 f2 [2] 65 e3 [2] 2b ef [2] 27 e5 [2] 30 ee [2] 2b a0 [2] 16 }

  condition:
    any of them
}