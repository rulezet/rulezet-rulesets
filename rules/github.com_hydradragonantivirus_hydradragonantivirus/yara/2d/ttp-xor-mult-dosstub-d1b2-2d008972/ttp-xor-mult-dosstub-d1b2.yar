rule TTP_XOR_MULT_DOSStub_d1b2 {
  strings:
    $key_d1b2 = { 85 da [2] f1 c2 [2] b6 c0 [2] f1 d1 [2] bf dd [2] b3 d7 [2] a4 dc [2] bf 92 [2] 82 }

  condition:
    any of them
}