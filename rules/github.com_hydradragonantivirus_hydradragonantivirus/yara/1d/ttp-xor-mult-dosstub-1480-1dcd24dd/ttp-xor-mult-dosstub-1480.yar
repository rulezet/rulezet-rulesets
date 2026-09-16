rule TTP_XOR_MULT_DOSStub_1480 {
  strings:
    $key_1480 = { 40 e8 [2] 34 f0 [2] 73 f2 [2] 34 e3 [2] 7a ef [2] 76 e5 [2] 61 ee [2] 7a a0 [2] 47 }

  condition:
    any of them
}