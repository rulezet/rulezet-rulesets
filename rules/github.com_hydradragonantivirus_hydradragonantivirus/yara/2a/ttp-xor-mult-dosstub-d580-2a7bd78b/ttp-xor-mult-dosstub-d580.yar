rule TTP_XOR_MULT_DOSStub_d580 {
  strings:
    $key_d580 = { 81 e8 [2] f5 f0 [2] b2 f2 [2] f5 e3 [2] bb ef [2] b7 e5 [2] a0 ee [2] bb a0 [2] 86 }

  condition:
    any of them
}