rule TTP_XOR_MULT_DOSStub_83d5 {
  strings:
    $key_83d5 = { d7 bd [2] a3 a5 [2] e4 a7 [2] a3 b6 [2] ed ba [2] e1 b0 [2] f6 bb [2] ed f5 [2] d0 }

  condition:
    any of them
}