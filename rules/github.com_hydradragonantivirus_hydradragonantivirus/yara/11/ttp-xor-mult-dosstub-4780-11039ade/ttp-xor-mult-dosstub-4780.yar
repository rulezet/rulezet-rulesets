rule TTP_XOR_MULT_DOSStub_4780 {
  strings:
    $key_4780 = { 13 e8 [2] 67 f0 [2] 20 f2 [2] 67 e3 [2] 29 ef [2] 25 e5 [2] 32 ee [2] 29 a0 [2] 14 }

  condition:
    any of them
}