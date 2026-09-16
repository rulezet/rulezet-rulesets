rule TTP_XOR_MULT_DOSStub_d6d4 {
  strings:
    $key_d6d4 = { 82 bc [2] f6 a4 [2] b1 a6 [2] f6 b7 [2] b8 bb [2] b4 b1 [2] a3 ba [2] b8 f4 [2] 85 }

  condition:
    any of them
}