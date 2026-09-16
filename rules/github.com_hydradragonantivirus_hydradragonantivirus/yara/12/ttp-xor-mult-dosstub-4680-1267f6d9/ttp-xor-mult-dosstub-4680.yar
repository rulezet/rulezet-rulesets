rule TTP_XOR_MULT_DOSStub_4680 {
  strings:
    $key_4680 = { 12 e8 [2] 66 f0 [2] 21 f2 [2] 66 e3 [2] 28 ef [2] 24 e5 [2] 33 ee [2] 28 a0 [2] 15 }

  condition:
    any of them
}