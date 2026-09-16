rule TTP_XOR_MULT_DOSStub_d0d4 {
  strings:
    $key_d0d4 = { 84 bc [2] f0 a4 [2] b7 a6 [2] f0 b7 [2] be bb [2] b2 b1 [2] a5 ba [2] be f4 [2] 83 }

  condition:
    any of them
}