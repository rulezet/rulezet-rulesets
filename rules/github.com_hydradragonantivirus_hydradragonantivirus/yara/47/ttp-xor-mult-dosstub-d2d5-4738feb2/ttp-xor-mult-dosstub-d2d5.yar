rule TTP_XOR_MULT_DOSStub_d2d5 {
  strings:
    $key_d2d5 = { 86 bd [2] f2 a5 [2] b5 a7 [2] f2 b6 [2] bc ba [2] b0 b0 [2] a7 bb [2] bc f5 [2] 81 }

  condition:
    any of them
}