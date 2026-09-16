rule TTP_XOR_MULT_DOSStub_8387 {
  strings:
    $key_8387 = { d7 ef [2] a3 f7 [2] e4 f5 [2] a3 e4 [2] ed e8 [2] e1 e2 [2] f6 e9 [2] ed a7 [2] d0 }

  condition:
    any of them
}