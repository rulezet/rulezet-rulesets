rule TTP_XOR_MULT_DOSStub_c7d2 {
  strings:
    $key_c7d2 = { 93 ba [2] e7 a2 [2] a0 a0 [2] e7 b1 [2] a9 bd [2] a5 b7 [2] b2 bc [2] a9 f2 [2] 94 }

  condition:
    any of them
}