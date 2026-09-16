rule TTP_XOR_MULT_DOSStub_8380 {
  strings:
    $key_8380 = { d7 e8 [2] a3 f0 [2] e4 f2 [2] a3 e3 [2] ed ef [2] e1 e5 [2] f6 ee [2] ed a0 [2] d0 }

  condition:
    any of them
}