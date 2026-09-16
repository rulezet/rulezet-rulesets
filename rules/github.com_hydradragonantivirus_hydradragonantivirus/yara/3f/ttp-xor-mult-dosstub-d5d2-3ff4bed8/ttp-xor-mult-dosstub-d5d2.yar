rule TTP_XOR_MULT_DOSStub_d5d2 {
  strings:
    $key_d5d2 = { 81 ba [2] f5 a2 [2] b2 a0 [2] f5 b1 [2] bb bd [2] b7 b7 [2] a0 bc [2] bb f2 [2] 86 }

  condition:
    any of them
}