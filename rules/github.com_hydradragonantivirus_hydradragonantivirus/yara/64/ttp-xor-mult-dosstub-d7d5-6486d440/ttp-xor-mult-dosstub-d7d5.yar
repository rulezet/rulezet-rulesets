rule TTP_XOR_MULT_DOSStub_d7d5 {
  strings:
    $key_d7d5 = { 83 bd [2] f7 a5 [2] b0 a7 [2] f7 b6 [2] b9 ba [2] b5 b0 [2] a2 bb [2] b9 f5 [2] 84 }

  condition:
    any of them
}