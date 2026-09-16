rule TTP_XOR_MULT_DOSStub_c7d4 {
  strings:
    $key_c7d4 = { 93 bc [2] e7 a4 [2] a0 a6 [2] e7 b7 [2] a9 bb [2] a5 b1 [2] b2 ba [2] a9 f4 [2] 94 }

  condition:
    any of them
}