rule TTP_XOR_MULT_DOSStub_2181 {
  strings:
    $key_2181 = { 75 e9 [2] 01 f1 [2] 46 f3 [2] 01 e2 [2] 4f ee [2] 43 e4 [2] 54 ef [2] 4f a1 [2] 72 }

  condition:
    any of them
}