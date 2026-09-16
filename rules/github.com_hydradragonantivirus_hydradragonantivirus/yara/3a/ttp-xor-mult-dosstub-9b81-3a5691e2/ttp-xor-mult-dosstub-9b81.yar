rule TTP_XOR_MULT_DOSStub_9b81 {
  strings:
    $key_9b81 = { cf e9 [2] bb f1 [2] fc f3 [2] bb e2 [2] f5 ee [2] f9 e4 [2] ee ef [2] f5 a1 [2] c8 }

  condition:
    any of them
}