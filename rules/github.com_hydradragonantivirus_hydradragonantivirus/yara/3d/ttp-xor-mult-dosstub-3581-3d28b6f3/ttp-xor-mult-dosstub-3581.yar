rule TTP_XOR_MULT_DOSStub_3581 {
  strings:
    $key_3581 = { 61 e9 [2] 15 f1 [2] 52 f3 [2] 15 e2 [2] 5b ee [2] 57 e4 [2] 40 ef [2] 5b a1 [2] 66 }

  condition:
    any of them
}