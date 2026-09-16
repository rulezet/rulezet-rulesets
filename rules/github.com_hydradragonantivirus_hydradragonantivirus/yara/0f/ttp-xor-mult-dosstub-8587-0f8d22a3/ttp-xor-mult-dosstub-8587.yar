rule TTP_XOR_MULT_DOSStub_8587 {
  strings:
    $key_8587 = { d1 ef [2] a5 f7 [2] e2 f5 [2] a5 e4 [2] eb e8 [2] e7 e2 [2] f0 e9 [2] eb a7 [2] d6 }

  condition:
    any of them
}