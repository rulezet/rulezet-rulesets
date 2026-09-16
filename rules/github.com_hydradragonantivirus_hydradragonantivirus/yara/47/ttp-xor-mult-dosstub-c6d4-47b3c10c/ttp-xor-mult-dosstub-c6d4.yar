rule TTP_XOR_MULT_DOSStub_c6d4 {
  strings:
    $key_c6d4 = { 92 bc [2] e6 a4 [2] a1 a6 [2] e6 b7 [2] a8 bb [2] a4 b1 [2] b3 ba [2] a8 f4 [2] 95 }

  condition:
    any of them
}