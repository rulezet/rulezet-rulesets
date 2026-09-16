rule TTP_XOR_MULT_DOSStub_d1b1 {
  strings:
    $key_d1b1 = { 85 d9 [2] f1 c1 [2] b6 c3 [2] f1 d2 [2] bf de [2] b3 d4 [2] a4 df [2] bf 91 [2] 82 }

  condition:
    any of them
}