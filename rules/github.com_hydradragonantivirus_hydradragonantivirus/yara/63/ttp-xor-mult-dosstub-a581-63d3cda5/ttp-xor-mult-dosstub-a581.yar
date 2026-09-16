rule TTP_XOR_MULT_DOSStub_a581 {
  strings:
    $key_a581 = { f1 e9 [2] 85 f1 [2] c2 f3 [2] 85 e2 [2] cb ee [2] c7 e4 [2] d0 ef [2] cb a1 [2] f6 }

  condition:
    any of them
}