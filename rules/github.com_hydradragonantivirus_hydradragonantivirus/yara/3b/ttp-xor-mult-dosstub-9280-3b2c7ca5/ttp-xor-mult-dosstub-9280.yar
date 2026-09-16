rule TTP_XOR_MULT_DOSStub_9280 {
  strings:
    $key_9280 = { c6 e8 [2] b2 f0 [2] f5 f2 [2] b2 e3 [2] fc ef [2] f0 e5 [2] e7 ee [2] fc a0 [2] c1 }

  condition:
    any of them
}