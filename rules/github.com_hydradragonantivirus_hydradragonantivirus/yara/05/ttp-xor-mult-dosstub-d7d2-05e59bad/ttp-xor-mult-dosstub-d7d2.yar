rule TTP_XOR_MULT_DOSStub_d7d2 {
  strings:
    $key_d7d2 = { 83 ba [2] f7 a2 [2] b0 a0 [2] f7 b1 [2] b9 bd [2] b5 b7 [2] a2 bc [2] b9 f2 [2] 84 }

  condition:
    any of them
}