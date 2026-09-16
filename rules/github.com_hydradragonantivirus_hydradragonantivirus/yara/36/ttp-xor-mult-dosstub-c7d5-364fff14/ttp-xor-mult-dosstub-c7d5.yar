rule TTP_XOR_MULT_DOSStub_c7d5 {
  strings:
    $key_c7d5 = { 93 bd [2] e7 a5 [2] a0 a7 [2] e7 b6 [2] a9 ba [2] a5 b0 [2] b2 bb [2] a9 f5 [2] 94 }

  condition:
    any of them
}