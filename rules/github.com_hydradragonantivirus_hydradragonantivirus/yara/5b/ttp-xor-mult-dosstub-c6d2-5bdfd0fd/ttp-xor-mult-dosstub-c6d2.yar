rule TTP_XOR_MULT_DOSStub_c6d2 {
  strings:
    $key_c6d2 = { 92 ba [2] e6 a2 [2] a1 a0 [2] e6 b1 [2] a8 bd [2] a4 b7 [2] b3 bc [2] a8 f2 [2] 95 }

  condition:
    any of them
}