rule TTP_XOR_MULT_DOSStub_d7d4 {
  strings:
    $key_d7d4 = { 83 bc [2] f7 a4 [2] b0 a6 [2] f7 b7 [2] b9 bb [2] b5 b1 [2] a2 ba [2] b9 f4 [2] 84 }

  condition:
    any of them
}