rule TTP_XOR_MULT_DOSStub_0481 {
  strings:
    $key_0481 = { 50 e9 [2] 24 f1 [2] 63 f3 [2] 24 e2 [2] 6a ee [2] 66 e4 [2] 71 ef [2] 6a a1 [2] 57 }

  condition:
    any of them
}