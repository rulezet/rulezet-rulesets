rule TTP_XOR_MULT_DOSStub_93d5 {
  strings:
    $key_93d5 = { c7 bd [2] b3 a5 [2] f4 a7 [2] b3 b6 [2] fd ba [2] f1 b0 [2] e6 bb [2] fd f5 [2] c0 }

  condition:
    any of them
}