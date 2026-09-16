rule TTP_XOR_MULT_DOSStub_91d5 {
  strings:
    $key_91d5 = { c5 bd [2] b1 a5 [2] f6 a7 [2] b1 b6 [2] ff ba [2] f3 b0 [2] e4 bb [2] ff f5 [2] c2 }

  condition:
    any of them
}