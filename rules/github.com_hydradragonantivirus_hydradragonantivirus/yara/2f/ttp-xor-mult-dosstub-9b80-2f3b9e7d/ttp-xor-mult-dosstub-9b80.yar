rule TTP_XOR_MULT_DOSStub_9b80 {
  strings:
    $key_9b80 = { cf e8 [2] bb f0 [2] fc f2 [2] bb e3 [2] f5 ef [2] f9 e5 [2] ee ee [2] f5 a0 [2] c8 }

  condition:
    any of them
}