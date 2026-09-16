rule TTP_XOR_MULT_DOSStub_8581 {
  strings:
    $key_8581 = { d1 e9 [2] a5 f1 [2] e2 f3 [2] a5 e2 [2] eb ee [2] e7 e4 [2] f0 ef [2] eb a1 [2] d6 }

  condition:
    any of them
}