rule TTP_XOR_MULT_DOSStub_c1d2 {
  strings:
    $key_c1d2 = { 95 ba [2] e1 a2 [2] a6 a0 [2] e1 b1 [2] af bd [2] a3 b7 [2] b4 bc [2] af f2 [2] 92 }

  condition:
    any of them
}