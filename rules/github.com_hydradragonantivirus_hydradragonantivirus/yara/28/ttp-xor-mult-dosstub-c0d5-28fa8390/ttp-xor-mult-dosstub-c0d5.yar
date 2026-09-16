rule TTP_XOR_MULT_DOSStub_c0d5 {
  strings:
    $key_c0d5 = { 94 bd [2] e0 a5 [2] a7 a7 [2] e0 b6 [2] ae ba [2] a2 b0 [2] b5 bb [2] ae f5 [2] 93 }

  condition:
    any of them
}