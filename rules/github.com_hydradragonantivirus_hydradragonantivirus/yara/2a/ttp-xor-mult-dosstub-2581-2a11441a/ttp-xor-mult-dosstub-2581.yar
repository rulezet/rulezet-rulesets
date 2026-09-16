rule TTP_XOR_MULT_DOSStub_2581 {
  strings:
    $key_2581 = { 71 e9 [2] 05 f1 [2] 42 f3 [2] 05 e2 [2] 4b ee [2] 47 e4 [2] 50 ef [2] 4b a1 [2] 76 }

  condition:
    any of them
}