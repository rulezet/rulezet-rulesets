rule TTP_XOR_MULT_DOSStub_8680 {
  strings:
    $key_8680 = { d2 e8 [2] a6 f0 [2] e1 f2 [2] a6 e3 [2] e8 ef [2] e4 e5 [2] f3 ee [2] e8 a0 [2] d5 }

  condition:
    any of them
}