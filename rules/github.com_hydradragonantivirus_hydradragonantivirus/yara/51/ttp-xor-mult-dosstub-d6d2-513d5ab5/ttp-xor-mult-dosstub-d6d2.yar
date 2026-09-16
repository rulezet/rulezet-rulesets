rule TTP_XOR_MULT_DOSStub_d6d2 {
  strings:
    $key_d6d2 = { 82 ba [2] f6 a2 [2] b1 a0 [2] f6 b1 [2] b8 bd [2] b4 b7 [2] a3 bc [2] b8 f2 [2] 85 }

  condition:
    any of them
}