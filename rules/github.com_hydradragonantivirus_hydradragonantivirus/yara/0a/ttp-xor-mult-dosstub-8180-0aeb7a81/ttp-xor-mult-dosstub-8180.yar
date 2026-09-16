rule TTP_XOR_MULT_DOSStub_8180 {
  strings:
    $key_8180 = { d5 e8 [2] a1 f0 [2] e6 f2 [2] a1 e3 [2] ef ef [2] e3 e5 [2] f4 ee [2] ef a0 [2] d2 }

  condition:
    any of them
}